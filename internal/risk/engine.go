package risk

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"containgo.local/containgo/internal/domain"
)

const ObservationWindow = 60 * time.Second

// EvaluationResult describes the outcome after processing one security event.
type EvaluationResult struct {
	WorkloadID       string                    `json:"workload_id"`
	PreviousScore    int                       `json:"previous_score"`
	Score            int                       `json:"score"`
	RequestCount     int                       `json:"request_count_60s"`
	DeniedCount      int                       `json:"denied_count_60s"`
	Contributions    []domain.RiskContribution `json:"contributions"`
	Quarantined      bool                      `json:"quarantined"`
	NewlyQuarantined bool                      `json:"newly_quarantined"`
}

// Snapshot is a read-only view of a workload's current risk-engine state.
type Snapshot struct {
	WorkloadID  string `json:"workload_id"`
	Score       int    `json:"score"`
	Quarantined bool   `json:"quarantined"`
}

type workloadState struct {
	score                  int
	quarantined            bool
	deniedThresholdActive  bool
	requestThresholdActive bool
}

// Engine evaluates security events and maintains the current in-memory
// risk state for each workload.
//
// SQLite becomes the persistent source of truth in Phase 2. This in-memory
// engine remains responsible for calculating contributions and thresholds.
type Engine struct {
	mu sync.Mutex

	requestWindow *Window
	deniedWindow  *Window
	states        map[string]*workloadState
}

// NewEngine creates a risk engine using rolling 60-second windows.
func NewEngine(clock Clock) (*Engine, error) {
	if clock == nil {
		return nil, errors.New("clock must not be nil")
	}

	requestWindow, err := NewWindow(
		ObservationWindow,
		clock,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"create request window: %w",
			err,
		)
	}

	deniedWindow, err := NewWindow(
		ObservationWindow,
		clock,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"create denied-request window: %w",
			err,
		)
	}

	return &Engine{
		requestWindow: requestWindow,
		deniedWindow:  deniedWindow,
		states:        make(map[string]*workloadState),
	}, nil
}

// Evaluate validates and evaluates one security event.
//
// Risk points are calculated from trusted event properties. Callers cannot
// provide their own point values.
func (e *Engine) Evaluate(
	event domain.SecurityEvent,
) (EvaluationResult, error) {
	if err := event.Validate(); err != nil {
		return EvaluationResult{}, fmt.Errorf(
			"validate security event: %w",
			err,
		)
	}

	workloadID := strings.TrimSpace(event.WorkloadID)

	if !domain.IsKnownWorkloadID(workloadID) {
		return EvaluationResult{}, fmt.Errorf(
			"unknown workload SPIFFE ID %q",
			workloadID,
		)
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	requestCount, err := e.requestWindow.Add(workloadID)
	if err != nil {
		return EvaluationResult{}, fmt.Errorf(
			"record request observation: %w",
			err,
		)
	}

	deniedCount, err := e.deniedWindow.Count(workloadID)
	if err != nil {
		return EvaluationResult{}, fmt.Errorf(
			"count denied observations: %w",
			err,
		)
	}

	if event.IsDenied() {
		deniedCount, err = e.deniedWindow.Add(workloadID)
		if err != nil {
			return EvaluationResult{}, fmt.Errorf(
				"record denied observation: %w",
				err,
			)
		}
	}

	state := e.states[workloadID]
	if state == nil {
		state = &workloadState{}
		e.states[workloadID] = state
	}

	// Re-arm each threshold after its rolling count falls below
	// the configured boundary.
	if requestCount <= 30 {
		state.requestThresholdActive = false
	}

	if deniedCount < 5 {
		state.deniedThresholdActive = false
	}

	result := EvaluationResult{
		WorkloadID:       workloadID,
		PreviousScore:    state.score,
		Score:            state.score,
		RequestCount:     requestCount,
		DeniedCount:      deniedCount,
		Contributions:    []domain.RiskContribution{},
		Quarantined:      state.quarantined,
		NewlyQuarantined: false,
	}

	// Once quarantined, the active incident score remains stable.
	// OPA will deny subsequent requests immediately.
	if state.quarantined {
		return result, nil
	}

	contributions := make(
		[]domain.RiskContribution,
		0,
		4,
	)

	addContribution := func(
		rule domain.RiskRule,
		reason string,
	) error {
		contribution, contributionErr :=
			domain.NewRiskContribution(rule, reason)
		if contributionErr != nil {
			return contributionErr
		}

		contributions = append(
			contributions,
			contribution,
		)

		return nil
	}

	if !IsAuthorizedRequest(
		workloadID,
		event.Method,
		event.Path,
	) {
		if err := addContribution(
			domain.RiskRuleUnauthorizedEndpoint,
			"workload is not authorized for the requested endpoint",
		); err != nil {
			return EvaluationResult{}, fmt.Errorf(
				"create unauthorized-endpoint contribution: %w",
				err,
			)
		}
	}

	sensitivity := ClassifyEndpoint(event.Path)

	if rule, found := SensitivityRiskRule(sensitivity); found {
		if err := addContribution(
			rule,
			fmt.Sprintf(
				"attempted access to %s",
				event.Path,
			),
		); err != nil {
			return EvaluationResult{}, fmt.Errorf(
				"create endpoint-sensitivity contribution: %w",
				err,
			)
		}
	}

	if deniedCount >= 5 &&
		!state.deniedThresholdActive {
		if err := addContribution(
			domain.RiskRuleFiveDeniedRequests,
			"five denied requests observed within 60 seconds",
		); err != nil {
			return EvaluationResult{}, fmt.Errorf(
				"create denied-request contribution: %w",
				err,
			)
		}

		state.deniedThresholdActive = true
	}

	if requestCount > 30 &&
		!state.requestThresholdActive {
		if err := addContribution(
			domain.RiskRuleHighRequestRate,
			"more than 30 requests observed within 60 seconds",
		); err != nil {
			return EvaluationResult{}, fmt.Errorf(
				"create request-rate contribution: %w",
				err,
			)
		}

		state.requestThresholdActive = true
	}

	for _, contribution := range contributions {
		state.score += contribution.Points
	}

	newlyQuarantined :=
		!state.quarantined &&
			domain.ReachesQuarantineThreshold(state.score)

	if newlyQuarantined {
		state.quarantined = true
	}

	result.Score = state.score
	result.Contributions = contributions
	result.Quarantined = state.quarantined
	result.NewlyQuarantined = newlyQuarantined

	return result, nil
}

// Observation represents one restored request-window observation.
type Observation struct {
	OccurredAt time.Time `json:"occurred_at"`
	Denied     bool      `json:"denied"`
}

// Restore rebuilds one workload's in-memory score, quarantine state, and
// rolling request observations from SQLite.
func (e *Engine) Restore(
	workloadID string,
	score int,
	quarantined bool,
	observations []Observation,
) error {
	workloadID = strings.TrimSpace(workloadID)

	if !domain.IsKnownWorkloadID(workloadID) {
		return fmt.Errorf(
			"unknown workload SPIFFE ID %q",
			workloadID,
		)
	}

	if score < 0 {
		return errors.New(
			"restored risk score must not be negative",
		)
	}

	if quarantined &&
		!domain.ReachesQuarantineThreshold(score) {
		return fmt.Errorf(
			"quarantined workload score must be at least %d",
			domain.QuarantineThreshold,
		)
	}

	requestTimes := make(
		[]time.Time,
		0,
		len(observations),
	)
	deniedTimes := make(
		[]time.Time,
		0,
		len(observations),
	)

	for index, observation := range observations {
		if observation.OccurredAt.IsZero() {
			return fmt.Errorf(
				"restored observation %d timestamp must not be zero",
				index,
			)
		}

		requestTimes = append(
			requestTimes,
			observation.OccurredAt.UTC(),
		)

		if observation.Denied {
			deniedTimes = append(
				deniedTimes,
				observation.OccurredAt.UTC(),
			)
		}
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	requestCount, err := e.requestWindow.Restore(
		workloadID,
		requestTimes,
	)
	if err != nil {
		return fmt.Errorf(
			"restore request window: %w",
			err,
		)
	}

	deniedCount, err := e.deniedWindow.Restore(
		workloadID,
		deniedTimes,
	)
	if err != nil {
		return fmt.Errorf(
			"restore denied-request window: %w",
			err,
		)
	}

	e.states[workloadID] = &workloadState{
		score:                  score,
		quarantined:            quarantined,
		deniedThresholdActive:  deniedCount >= 5,
		requestThresholdActive: requestCount > 30,
	}

	return nil
}

// Snapshot returns the current risk state for a workload.
func (e *Engine) Snapshot(
	workloadID string,
) (Snapshot, bool) {
	workloadID = strings.TrimSpace(workloadID)

	e.mu.Lock()
	defer e.mu.Unlock()

	state, found := e.states[workloadID]
	if !found {
		return Snapshot{}, false
	}

	return Snapshot{
		WorkloadID:  workloadID,
		Score:       state.score,
		Quarantined: state.quarantined,
	}, true
}

// Reset clears the current score, quarantine state, rolling counters,
// and threshold states for a workload.
func (e *Engine) Reset(workloadID string) error {
	workloadID = strings.TrimSpace(workloadID)

	if !domain.IsKnownWorkloadID(workloadID) {
		return fmt.Errorf(
			"unknown workload SPIFFE ID %q",
			workloadID,
		)
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	if err := e.requestWindow.Reset(workloadID); err != nil {
		return fmt.Errorf(
			"reset request window: %w",
			err,
		)
	}

	if err := e.deniedWindow.Reset(workloadID); err != nil {
		return fmt.Errorf(
			"reset denied-request window: %w",
			err,
		)
	}

	delete(e.states, workloadID)

	return nil
}
