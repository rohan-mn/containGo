package controlplane

import (
	"context"
	"net/http"
	"testing"
	"time"

	"containgo.local/containgo/internal/application"
	"containgo.local/containgo/internal/domain"
	"containgo.local/containgo/internal/repository"
	"containgo.local/containgo/internal/risk"
	"containgo.local/containgo/internal/testutil"
)

func TestServiceQuarantineStoresCompleteIncidentEvidence(t *testing.T) {
	ctx := context.Background()
	db := testutil.OpenSQLite(t)

	workloads, err := repository.NewSQLiteWorkloadRepository(db)
	if err != nil {
		t.Fatalf("create workload repository: %v", err)
	}

	events, err := repository.NewSQLiteEventRepository(db)
	if err != nil {
		t.Fatalf("create event repository: %v", err)
	}

	incidents, err := repository.NewSQLiteIncidentRepository(db)
	if err != nil {
		t.Fatalf("create incident repository: %v", err)
	}

	audits, err := repository.NewSQLiteAuditRepository(db)
	if err != nil {
		t.Fatalf("create audit repository: %v", err)
	}

	clock := &controlPlaneTestClock{
		now: time.Date(2026, time.June, 22, 6, 0, 0, 0, time.UTC),
	}

	engine, err := risk.NewEngine(clock)
	if err != nil {
		t.Fatalf("create risk engine: %v", err)
	}

	quarantine, err := application.NewQuarantineService(
		workloads,
		incidents,
		audits,
	)
	if err != nil {
		t.Fatalf("create quarantine service: %v", err)
	}

	release, err := application.NewReleaseService(
		workloads,
		incidents,
		audits,
	)
	if err != nil {
		t.Fatalf("create release service: %v", err)
	}

	enforcer := &controlPlaneTestEnforcer{}
	service, err := NewService(
		clock,
		engine,
		workloads,
		events,
		incidents,
		audits,
		quarantine,
		release,
		enforcer,
	)
	if err != nil {
		t.Fatalf("create control-plane service: %v", err)
	}

	if _, err = service.Reconcile(ctx); err != nil {
		t.Fatalf("reconcile service: %v", err)
	}

	first, err := service.Ingest(
		ctx,
		deniedTestEvent(
			"request-payment-details",
			"/api/payment-details",
			clock.Now(),
		),
	)
	if err != nil {
		t.Fatalf("ingest first denied event: %v", err)
	}

	if first.Evaluation.Score != 65 {
		t.Fatalf("first score = %d, want 65", first.Evaluation.Score)
	}

	if first.Incident != nil {
		t.Fatal("first event unexpectedly created an incident")
	}

	clock.Advance(time.Second)

	second, err := service.Ingest(
		ctx,
		deniedTestEvent(
			"request-admin-config",
			"/api/admin/config",
			clock.Now(),
		),
	)
	if err != nil {
		t.Fatalf("ingest second denied event: %v", err)
	}

	if second.Evaluation.Score != 125 {
		t.Fatalf("second score = %d, want 125", second.Evaluation.Score)
	}

	if second.Incident == nil {
		t.Fatal("second event did not create an incident")
	}

	if got := second.Incident.TotalReasonPoints(); got != 125 {
		t.Fatalf("incident reason points = %d, want 125", got)
	}

	if len(second.Incident.Reasons) != 4 {
		t.Fatalf("incident reason count = %d, want 4", len(second.Incident.Reasons))
	}

	if !enforcer.IsQuarantined(domain.SPIFFEIDReportClient) {
		t.Fatal("runtime enforcer was not updated")
	}

	storedIncidents, err := incidents.ListByWorkload(
		ctx,
		domain.SPIFFEIDReportClient,
		10,
	)
	if err != nil {
		t.Fatalf("list stored incidents: %v", err)
	}

	if len(storedIncidents) != 1 {
		t.Fatalf("stored incident count = %d, want 1", len(storedIncidents))
	}

	if got := storedIncidents[0].TotalReasonPoints(); got != storedIncidents[0].ScoreAtQuarantine {
		t.Fatalf(
			"stored reason points = %d, score = %d",
			got,
			storedIncidents[0].ScoreAtQuarantine,
		)
	}
}

type controlPlaneTestClock struct {
	now time.Time
}

func (c *controlPlaneTestClock) Now() time.Time {
	return c.now
}

func (c *controlPlaneTestClock) Advance(duration time.Duration) {
	c.now = c.now.Add(duration)
}

type controlPlaneTestEnforcer struct {
	quarantined map[string]bool
}

func (e *controlPlaneTestEnforcer) Check(context.Context) error {
	return nil
}

func (e *controlPlaneTestEnforcer) SetQuarantined(
	_ context.Context,
	spiffeID string,
	quarantined bool,
) error {
	if e.quarantined == nil {
		e.quarantined = make(map[string]bool)
	}

	e.quarantined[spiffeID] = quarantined
	return nil
}

func (e *controlPlaneTestEnforcer) ReplaceQuarantined(
	_ context.Context,
	spiffeIDs []string,
) error {
	e.quarantined = make(map[string]bool)
	for _, spiffeID := range spiffeIDs {
		e.quarantined[spiffeID] = true
	}
	return nil
}

func (e *controlPlaneTestEnforcer) IsQuarantined(spiffeID string) bool {
	return e.quarantined[spiffeID]
}

func deniedTestEvent(
	requestID string,
	path string,
	occurredAt time.Time,
) domain.SecurityEvent {
	return domain.SecurityEvent{
		RequestID:  requestID,
		WorkloadID: domain.SPIFFEIDReportClient,
		Method:     http.MethodGet,
		Path:       path,
		Decision:   domain.DecisionDenied,
		StatusCode: http.StatusForbidden,
		Reason:     "OPA denied the request",
		OccurredAt: occurredAt,
	}
}
