package controlservice

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"containgo.local/containgo/internal/platform"
)

type persistentState struct {
	Version   int                               `json:"version"`
	Sequence  int64                             `json:"sequence"`
	Workloads map[string]platform.WorkloadState `json:"workloads"`
	Events    []platform.StoredEvent            `json:"events"`
	Incidents []platform.Incident               `json:"incidents"`
}

type Store struct {
	mu              sync.RWMutex
	path            string
	threshold       int
	state           persistentState
	recent          map[string][]time.Time
	lastRatePenalty map[string]time.Time
}

func NewStore(path string, threshold int) (*Store, error) {
	if threshold <= 0 {
		threshold = 100
	}
	store := &Store{
		path:            path,
		threshold:       threshold,
		recent:          make(map[string][]time.Time),
		lastRatePenalty: make(map[string]time.Time),
		state: persistentState{
			Version:   1,
			Workloads: defaultWorkloads(),
			Events:    []platform.StoredEvent{},
			Incidents: []platform.Incident{},
		},
	}
	if err := store.load(); err != nil {
		return nil, err
	}
	store.ensureDefaults()
	return store, nil
}

func defaultWorkloads() map[string]platform.WorkloadState {
	definitions := []platform.WorkloadState{
		{Name: "api-gateway", SPIFFEID: "spiffe://containgo.local/ns/containgo/sa/api-gateway", Role: "SPIFFE mTLS ingress, OPA authorization, trusted event publisher", Status: "active"},
		{Name: "control-plane", SPIFFEID: "spiffe://containgo.local/ns/containgo/sa/control-plane", Role: "Risk scoring, quarantine decisions, incidents and evidence", Status: "active"},
		{Name: "dashboard", SPIFFEID: "spiffe://containgo.local/ns/containgo/sa/dashboard", Role: "Interactive architecture and administrative console", Status: "active"},
		{Name: "order-client", SPIFFEID: "spiffe://containgo.local/ns/containgo/sa/order-client", Role: "Order business workload and request generator", Status: "active"},
		{Name: "report-client", SPIFFEID: "spiffe://containgo.local/ns/containgo/sa/report-client", Role: "Reporting business workload and request generator", Status: "active"},
		{Name: "protected-api", SPIFFEID: "spiffe://containgo.local/ns/containgo/sa/protected-api", Role: "Protected CRUD API reachable through the Gateway", Status: "active"},
	}
	result := make(map[string]platform.WorkloadState, len(definitions))
	for _, workload := range definitions {
		result[workload.Name] = workload
	}
	return result
}

func (s *Store) ensureDefaults() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for name, workload := range defaultWorkloads() {
		if _, ok := s.state.Workloads[name]; !ok {
			s.state.Workloads[name] = workload
		}
	}
}

func (s *Store) load() error {
	if strings.TrimSpace(s.path) == "" {
		return nil
	}
	data, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var state persistentState
	if err := json.Unmarshal(data, &state); err != nil {
		return fmt.Errorf("decode control-plane state: %w", err)
	}
	if state.Workloads == nil {
		state.Workloads = defaultWorkloads()
	}
	s.state = state
	return nil
}

func (s *Store) persistLocked() error {
	if strings.TrimSpace(s.path) == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o750); err != nil {
		return err
	}
	data, err := json.MarshalIndent(s.state, "", "  ")
	if err != nil {
		return err
	}
	temp := s.path + ".tmp"
	if err := os.WriteFile(temp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(temp, s.path)
}

func (s *Store) Process(event platform.DecisionEvent, controlHop *platform.TraceHop) (platform.StoredEvent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	workload, ok := s.state.Workloads[event.Workload]
	if !ok {
		workload = platform.WorkloadState{Name: event.Workload, SPIFFEID: event.SPIFFEID, Role: "Observed workload", Status: "active"}
	}
	if workload.SPIFFEID == "" {
		workload.SPIFFEID = event.SPIFFEID
	}
	riskBefore := workload.RiskScore
	riskDelta, reasons := s.calculateRiskLocked(event, workload)
	workload.RiskScore += riskDelta
	workload.LastSeen = event.OccurredAt
	if workload.LastSeen.IsZero() {
		workload.LastSeen = time.Now().UTC()
	}
	workload.LastDecision = event.Decision
	workload.LastDecisionPath = event.Method + " " + event.Path
	if event.Decision == "allow" {
		workload.AllowedRequests++
	} else {
		workload.DeniedRequests++
	}

	quarantinedNow := false
	if workload.Status != "quarantined" && workload.RiskScore >= s.threshold {
		workload.Status = "quarantined"
		workload.QuarantinedAt = time.Now().UTC()
		quarantinedNow = true
		s.state.Incidents = append(s.state.Incidents, platform.Incident{
			ID:            platform.NewID("incident"),
			Workload:      workload.Name,
			SPIFFEID:      workload.SPIFFEID,
			OpenedAt:      workload.QuarantinedAt,
			Status:        "open",
			ScoreAtOpen:   workload.RiskScore,
			Threshold:     s.threshold,
			TriggerTrace:  event.TraceID,
			EvidenceCount: workload.DeniedRequests,
		})
	}
	s.state.Workloads[workload.Name] = workload
	s.state.Sequence++
	stored := platform.StoredEvent{
		Sequence:        s.state.Sequence,
		DecisionEvent:   event,
		RiskBefore:      riskBefore,
		RiskDelta:       riskDelta,
		RiskAfter:       workload.RiskScore,
		Quarantined:     quarantinedNow || workload.Status == "quarantined",
		RiskReasons:     reasons,
		ControlPlaneHop: controlHop,
	}
	s.state.Events = append(s.state.Events, stored)
	if len(s.state.Events) > 5000 {
		s.state.Events = append([]platform.StoredEvent(nil), s.state.Events[len(s.state.Events)-5000:]...)
	}
	if err := s.persistLocked(); err != nil {
		return platform.StoredEvent{}, err
	}
	return stored, nil
}

func (s *Store) calculateRiskLocked(event platform.DecisionEvent, workload platform.WorkloadState) (int, []string) {
	if workload.Name != "order-client" && workload.Name != "report-client" {
		return 0, nil
	}
	if workload.Status == "quarantined" {
		return 0, []string{"workload_already_quarantined"}
	}
	delta := 0
	reasons := []string{}
	if event.Decision != "allow" {
		delta += 25
		reasons = append(reasons, "unauthorized_request")
		if event.Path == "/api/payment-details" {
			delta += 40
			reasons = append(reasons, "highly_sensitive_endpoint_attempt")
		}
		if event.Path == "/api/admin/config" {
			delta += 35
			reasons = append(reasons, "administrative_endpoint_attempt")
		}
	}

	now := event.OccurredAt
	if now.IsZero() {
		now = time.Now().UTC()
	}
	windowStart := now.Add(-5 * time.Second)
	timestamps := s.recent[event.SPIFFEID]
	filtered := timestamps[:0]
	for _, timestamp := range timestamps {
		if timestamp.After(windowStart) {
			filtered = append(filtered, timestamp)
		}
	}
	filtered = append(filtered, now)
	s.recent[event.SPIFFEID] = filtered
	if len(filtered) > 20 && now.Sub(s.lastRatePenalty[event.SPIFFEID]) > 30*time.Second {
		delta += 50
		reasons = append(reasons, "rate_anomaly_over_20_requests_in_5_seconds")
		s.lastRatePenalty[event.SPIFFEID] = now
	}
	return delta, reasons
}

func (s *Store) Workloads() []platform.WorkloadState {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]platform.WorkloadState, 0, len(s.state.Workloads))
	for _, workload := range s.state.Workloads {
		result = append(result, workload)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Name < result[j].Name })
	return result
}

func (s *Store) Workload(name string) (platform.WorkloadState, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	workload, ok := s.state.Workloads[name]
	return workload, ok
}

func (s *Store) ResolveSPIFFEID(spiffeID string) (platform.WorkloadState, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, workload := range s.state.Workloads {
		if workload.SPIFFEID == spiffeID {
			return workload, true
		}
	}
	return platform.WorkloadState{}, false
}

func (s *Store) Events(after int64, limit int) []platform.StoredEvent {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	result := make([]platform.StoredEvent, 0, limit)
	for _, event := range s.state.Events {
		if event.Sequence > after {
			result = append(result, event)
		}
	}
	if len(result) > limit {
		result = result[len(result)-limit:]
	}
	return append([]platform.StoredEvent(nil), result...)
}

func (s *Store) Trace(traceID string) []platform.StoredEvent {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := []platform.StoredEvent{}
	for _, event := range s.state.Events {
		if event.DecisionEvent.TraceID == traceID {
			result = append(result, event)
		}
	}
	return result
}

func (s *Store) Incidents() []platform.Incident {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := append([]platform.Incident(nil), s.state.Incidents...)
	sort.Slice(result, func(i, j int) bool { return result[i].OpenedAt.After(result[j].OpenedAt) })
	return result
}

func (s *Store) Release(name, actor string) (platform.WorkloadState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	workload, ok := s.state.Workloads[name]
	if !ok {
		return platform.WorkloadState{}, errors.New("workload not found")
	}
	if workload.Status != "quarantined" {
		return platform.WorkloadState{}, errors.New("workload is not quarantined")
	}
	workload.Status = "active"
	workload.RiskScore = 0
	workload.QuarantinedAt = time.Time{}
	workload.LastDecision = "released by " + actor
	s.state.Workloads[name] = workload
	for index := len(s.state.Incidents) - 1; index >= 0; index-- {
		if s.state.Incidents[index].Workload == name && s.state.Incidents[index].Status == "open" {
			s.state.Incidents[index].Status = "resolved"
			s.state.Incidents[index].ResolvedAt = time.Now().UTC()
			s.state.Incidents[index].Resolution = "Released by " + actor
			break
		}
	}
	return workload, s.persistLocked()
}

func (s *Store) ResetRisk(name, actor string) (platform.WorkloadState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	workload, ok := s.state.Workloads[name]
	if !ok {
		return platform.WorkloadState{}, errors.New("workload not found")
	}
	if workload.Status == "quarantined" {
		return platform.WorkloadState{}, errors.New("release a quarantined workload instead of resetting it")
	}
	workload.RiskScore = 0
	workload.LastDecision = "risk reset by " + actor
	s.state.Workloads[name] = workload
	return workload, s.persistLocked()
}

func (s *Store) Threshold() int { return s.threshold }
