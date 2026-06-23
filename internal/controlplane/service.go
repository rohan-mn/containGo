package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"containgo.local/containgo/internal/application"
	"containgo.local/containgo/internal/domain"
	"containgo.local/containgo/internal/risk"
)

var (
	// ErrDuplicateEvent indicates that the request ID was already processed.
	ErrDuplicateEvent = errors.New("security event already exists")
)

// Service coordinates risk evaluation, persistence, quarantine enforcement,
// administrative release, and startup reconciliation.
type Service struct {
	mu sync.Mutex

	clock      Clock
	riskEngine RiskEngine
	workloads  WorkloadRepository
	events     EventRepository
	incidents  IncidentRepository
	audits     AuditRepository
	quarantine QuarantineWorkflow
	release    ReleaseWorkflow
	enforcer   QuarantineEnforcer
}

// NewService creates the control-plane application service.
func NewService(
	clock Clock,
	riskEngine RiskEngine,
	workloads WorkloadRepository,
	events EventRepository,
	incidents IncidentRepository,
	audits AuditRepository,
	quarantine QuarantineWorkflow,
	release ReleaseWorkflow,
	enforcer QuarantineEnforcer,
) (*Service, error) {
	if clock == nil {
		return nil, errors.New("clock must not be nil")
	}

	if riskEngine == nil {
		return nil, errors.New("risk engine must not be nil")
	}

	if workloads == nil {
		return nil, errors.New("workload repository must not be nil")
	}

	if events == nil {
		return nil, errors.New("event repository must not be nil")
	}

	if incidents == nil {
		return nil, errors.New("incident repository must not be nil")
	}

	if audits == nil {
		return nil, errors.New("audit repository must not be nil")
	}

	if quarantine == nil {
		return nil, errors.New("quarantine workflow must not be nil")
	}

	if release == nil {
		return nil, errors.New("release workflow must not be nil")
	}

	if enforcer == nil {
		return nil, errors.New("quarantine enforcer must not be nil")
	}

	return &Service{
		clock:      clock,
		riskEngine: riskEngine,
		workloads:  workloads,
		events:     events,
		incidents:  incidents,
		audits:     audits,
		quarantine: quarantine,
		release:    release,
		enforcer:   enforcer,
	}, nil
}

// ReconciliationResult summarizes startup restoration from SQLite into the
// in-memory risk engine and OPA quarantine data.
type ReconciliationResult struct {
	WorkloadCount    int      `json:"workload_count"`
	QuarantinedCount int      `json:"quarantined_count"`
	QuarantinedIDs   []string `json:"quarantined_spiffe_ids"`
}

// Reconcile rebuilds volatile risk windows and OPA data from SQLite.
func (s *Service) Reconcile(
	ctx context.Context,
) (ReconciliationResult, error) {
	if err := validateContext(ctx); err != nil {
		return ReconciliationResult{}, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.clock.Now().UTC()

	if err := s.workloads.EnsureKnown(ctx, now); err != nil {
		return ReconciliationResult{}, fmt.Errorf(
			"ensure known workloads: %w",
			err,
		)
	}

	workloads, err := s.workloads.List(ctx)
	if err != nil {
		return ReconciliationResult{}, fmt.Errorf(
			"list workloads for reconciliation: %w",
			err,
		)
	}

	quarantinedIDs := make([]string, 0)
	windowStart := now.Add(-risk.ObservationWindow)

	for _, workload := range workloads {
		storedEvents, listErr := s.events.ListByWorkload(
			ctx,
			workload.SPIFFEID,
			500,
		)
		if listErr != nil {
			return ReconciliationResult{}, fmt.Errorf(
				"list recent events for workload %q: %w",
				workload.SPIFFEID,
				listErr,
			)
		}

		observations := make(
			[]risk.Observation,
			0,
			len(storedEvents),
		)

		for _, storedEvent := range storedEvents {
			if storedEvent.Event.OccurredAt.Before(windowStart) {
				continue
			}

			if storedEvent.Event.OccurredAt.After(now) {
				continue
			}

			observations = append(
				observations,
				risk.Observation{
					OccurredAt: storedEvent.Event.OccurredAt,
					Denied:     storedEvent.Event.IsDenied(),
				},
			)
		}

		if restoreErr := s.riskEngine.Restore(
			workload.SPIFFEID,
			workload.RiskScore,
			workload.IsQuarantined(),
			observations,
		); restoreErr != nil {
			return ReconciliationResult{}, fmt.Errorf(
				"restore risk state for workload %q: %w",
				workload.SPIFFEID,
				restoreErr,
			)
		}

		if workload.IsQuarantined() {
			quarantinedIDs = append(
				quarantinedIDs,
				workload.SPIFFEID,
			)
		}
	}

	if err = s.enforcer.ReplaceQuarantined(
		ctx,
		quarantinedIDs,
	); err != nil {
		return ReconciliationResult{}, fmt.Errorf(
			"reconcile OPA quarantine data: %w",
			err,
		)
	}

	return ReconciliationResult{
		WorkloadCount:    len(workloads),
		QuarantinedCount: len(quarantinedIDs),
		QuarantinedIDs: append(
			[]string(nil),
			quarantinedIDs...,
		),
	}, nil
}

// IngestResult contains the complete outcome of one trusted security event.
type IngestResult struct {
	StoredEvent  domain.StoredEvent    `json:"stored_event"`
	Evaluation   risk.EvaluationResult `json:"evaluation"`
	Incident     *domain.Incident      `json:"incident,omitempty"`
	AuditRecords []domain.AuditRecord  `json:"audit_records,omitempty"`
}

// Ingest validates a trusted gateway event, calculates risk points internally,
// persists the result, and automatically quarantines at the threshold.
func (s *Service) Ingest(
	ctx context.Context,
	event domain.SecurityEvent,
) (IngestResult, error) {
	if err := validateContext(ctx); err != nil {
		return IngestResult{}, err
	}

	event.RequestID = strings.TrimSpace(event.RequestID)
	event.WorkloadID = strings.TrimSpace(event.WorkloadID)
	event.Method = domain.NormalizedMethod(event.Method)
	event.Path = strings.TrimSpace(event.Path)
	event.Reason = strings.TrimSpace(event.Reason)
	event.OccurredAt = event.OccurredAt.UTC()

	if err := event.Validate(); err != nil {
		return IngestResult{}, fmt.Errorf(
			"validate security event: %w",
			err,
		)
	}

	if !domain.IsKnownWorkloadID(event.WorkloadID) {
		return IngestResult{}, fmt.Errorf(
			"unknown workload SPIFFE ID %q",
			event.WorkloadID,
		)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	exists, err := s.events.ExistsByRequestID(
		ctx,
		event.RequestID,
	)
	if err != nil {
		return IngestResult{}, fmt.Errorf(
			"check duplicate security event: %w",
			err,
		)
	}

	if exists {
		return IngestResult{}, fmt.Errorf(
			"%w: request ID %q",
			ErrDuplicateEvent,
			event.RequestID,
		)
	}

	evaluation, err := s.riskEngine.Evaluate(event)
	if err != nil {
		return IngestResult{}, fmt.Errorf(
			"evaluate security event: %w",
			err,
		)
	}

	storedEvent, err := s.events.Create(
		ctx,
		event,
		evaluation.Contributions,
		s.clock.Now().UTC(),
	)
	if err != nil {
		return IngestResult{}, fmt.Errorf(
			"store security event: %w",
			err,
		)
	}

	if err = s.workloads.UpdateRisk(
		ctx,
		event.WorkloadID,
		evaluation.Score,
		evaluation.DeniedCount,
		event.OccurredAt,
	); err != nil {
		return IngestResult{
				StoredEvent: storedEvent,
				Evaluation:  evaluation,
			}, fmt.Errorf(
				"update workload risk state: %w",
				err,
			)
	}

	result := IngestResult{
		StoredEvent:  storedEvent,
		Evaluation:   evaluation,
		AuditRecords: []domain.AuditRecord{},
	}

	if !evaluation.NewlyQuarantined {
		return result, nil
	}

	incidentReasons, err := s.loadIncidentEvidence(
		ctx,
		event.WorkloadID,
		evaluation.Score,
	)
	if err != nil {
		return result, err
	}

	quarantineResult, err := s.quarantine.Quarantine(
		ctx,
		application.QuarantineRequest{
			WorkloadSPIFFEID: event.WorkloadID,
			ActorSPIFFEID:    domain.SPIFFEIDControlPlane,
			Score:            evaluation.Score,
			Reasons:          incidentReasons,
			OccurredAt:       event.OccurredAt,
		},
	)
	if err != nil {
		return result, fmt.Errorf(
			"execute automatic quarantine: %w",
			err,
		)
	}

	result.Incident = &quarantineResult.Incident
	result.AuditRecords = append(
		result.AuditRecords,
		quarantineResult.AuditRecords...,
	)

	if err = s.enforcer.SetQuarantined(
		ctx,
		event.WorkloadID,
		true,
	); err != nil {
		return result, fmt.Errorf(
			"add workload to OPA quarantine data: %w",
			err,
		)
	}

	opaAudit, err := s.createAudit(
		ctx,
		domain.AuditActionOPAQuarantineAdded,
		domain.SPIFFEIDControlPlane,
		event.WorkloadID,
		map[string]any{
			"incident_id": quarantineResult.Incident.ID,
			"score":       evaluation.Score,
		},
		event.OccurredAt,
	)
	if err != nil {
		return result, fmt.Errorf(
			"store OPA quarantine audit record: %w",
			err,
		)
	}

	result.AuditRecords = append(
		result.AuditRecords,
		opaAudit,
	)

	return result, nil
}

// Release closes the open incident, reactivates the workload, resets the risk
// engine, and removes the workload from OPA quarantine data.
func (s *Service) Release(
	ctx context.Context,
	workloadSPIFFEID string,
	actorSPIFFEID string,
) (application.ReleaseResult, error) {
	if err := validateContext(ctx); err != nil {
		return application.ReleaseResult{}, err
	}

	workloadSPIFFEID = strings.TrimSpace(workloadSPIFFEID)
	actorSPIFFEID = strings.TrimSpace(actorSPIFFEID)

	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.clock.Now().UTC()

	result, err := s.release.Release(
		ctx,
		application.ReleaseRequest{
			WorkloadSPIFFEID: workloadSPIFFEID,
			ActorSPIFFEID:    actorSPIFFEID,
			OccurredAt:       now,
		},
	)
	if err != nil {
		return result, err
	}

	if err = s.riskEngine.Reset(workloadSPIFFEID); err != nil {
		return result, fmt.Errorf(
			"reset in-memory risk state: %w",
			err,
		)
	}

	if err = s.enforcer.SetQuarantined(
		ctx,
		workloadSPIFFEID,
		false,
	); err != nil {
		return result, fmt.Errorf(
			"remove workload from OPA quarantine data: %w",
			err,
		)
	}

	opaAudit, err := s.createAudit(
		ctx,
		domain.AuditActionOPAQuarantineRemoved,
		actorSPIFFEID,
		workloadSPIFFEID,
		map[string]any{
			"incident_id": result.Incident.ID,
		},
		now,
	)
	if err != nil {
		return result, fmt.Errorf(
			"store OPA release audit record: %w",
			err,
		)
	}

	result.AuditRecords = append(
		result.AuditRecords,
		opaAudit,
	)

	return result, nil
}

// ResetRisk clears score and rolling-window state for an active workload.
func (s *Service) ResetRisk(
	ctx context.Context,
	workloadSPIFFEID string,
	actorSPIFFEID string,
) (domain.Workload, error) {
	if err := validateContext(ctx); err != nil {
		return domain.Workload{}, err
	}

	workloadSPIFFEID = strings.TrimSpace(workloadSPIFFEID)
	actorSPIFFEID = strings.TrimSpace(actorSPIFFEID)

	if !domain.IsKnownWorkloadID(actorSPIFFEID) {
		return domain.Workload{}, fmt.Errorf(
			"unknown reset actor SPIFFE ID %q",
			actorSPIFFEID,
		)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	before, err := s.workloads.FindBySPIFFEID(
		ctx,
		workloadSPIFFEID,
	)
	if err != nil {
		return domain.Workload{}, fmt.Errorf(
			"find workload before risk reset: %w",
			err,
		)
	}

	now := s.clock.Now().UTC()

	if err = s.workloads.ResetRisk(
		ctx,
		workloadSPIFFEID,
		now,
	); err != nil {
		return domain.Workload{}, fmt.Errorf(
			"reset persisted workload risk: %w",
			err,
		)
	}

	if err = s.riskEngine.Reset(workloadSPIFFEID); err != nil {
		return domain.Workload{}, fmt.Errorf(
			"reset in-memory workload risk: %w",
			err,
		)
	}

	if _, err = s.createAudit(
		ctx,
		domain.AuditActionRiskReset,
		actorSPIFFEID,
		workloadSPIFFEID,
		map[string]any{
			"previous_score":           before.RiskScore,
			"previous_denied_requests": before.DeniedRequests,
			"new_score":                0,
		},
		now,
	); err != nil {
		return domain.Workload{}, fmt.Errorf(
			"store risk-reset audit record: %w",
			err,
		)
	}

	workload, err := s.workloads.FindBySPIFFEID(
		ctx,
		workloadSPIFFEID,
	)
	if err != nil {
		return domain.Workload{}, fmt.Errorf(
			"find workload after risk reset: %w",
			err,
		)
	}

	return workload, nil
}

// Check reports ready only when SQLite access and the policy enforcer work.
func (s *Service) Check(ctx context.Context) error {
	if err := validateContext(ctx); err != nil {
		return err
	}

	if _, err := s.workloads.List(ctx); err != nil {
		return fmt.Errorf("database readiness: %w", err)
	}

	if err := s.enforcer.Check(ctx); err != nil {
		return fmt.Errorf("quarantine enforcer readiness: %w", err)
	}

	return nil
}

// ListWorkloads returns the current persisted workload states.
func (s *Service) ListWorkloads(
	ctx context.Context,
) ([]domain.Workload, error) {
	return s.workloads.List(ctx)
}

// FindWorkload returns one current persisted workload state.
func (s *Service) FindWorkload(
	ctx context.Context,
	spiffeID string,
) (domain.Workload, error) {
	return s.workloads.FindBySPIFFEID(ctx, spiffeID)
}

// ListEvents returns one workload's newest events.
func (s *Service) ListEvents(
	ctx context.Context,
	spiffeID string,
	limit int,
) ([]domain.StoredEvent, error) {
	return s.events.ListByWorkload(ctx, spiffeID, limit)
}

// ListIncidents returns one workload's newest incidents.
func (s *Service) ListIncidents(
	ctx context.Context,
	spiffeID string,
	limit int,
) ([]domain.Incident, error) {
	return s.incidents.ListByWorkload(ctx, spiffeID, limit)
}

// ListAudit returns recent audit records, optionally filtered by target.
func (s *Service) ListAudit(
	ctx context.Context,
	targetSPIFFEID string,
	limit int,
) ([]domain.AuditRecord, error) {
	if strings.TrimSpace(targetSPIFFEID) == "" {
		return s.audits.ListRecent(ctx, limit)
	}

	return s.audits.ListByTarget(
		ctx,
		targetSPIFFEID,
		limit,
	)
}

func (s *Service) createAudit(
	ctx context.Context,
	action domain.AuditAction,
	actorSPIFFEID string,
	targetSPIFFEID string,
	details map[string]any,
	occurredAt time.Time,
) (domain.AuditRecord, error) {
	detailsJSON, err := json.Marshal(details)
	if err != nil {
		return domain.AuditRecord{}, fmt.Errorf(
			"encode audit details: %w",
			err,
		)
	}

	return s.audits.Create(
		ctx,
		domain.AuditRecord{
			ActorSPIFFEID:  actorSPIFFEID,
			Action:         action,
			TargetSPIFFEID: targetSPIFFEID,
			DetailsJSON:    detailsJSON,
			OccurredAt:     occurredAt.UTC(),
		},
	)
}

func validateContext(ctx context.Context) error {
	if ctx == nil {
		return errors.New("context must not be nil")
	}

	if err := ctx.Err(); err != nil {
		return fmt.Errorf("context is not usable: %w", err)
	}

	return nil
}
