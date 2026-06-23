package application

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"containgo.local/containgo/internal/domain"
)

func TestQuarantineServiceSuccess(
	t *testing.T,
) {
	now := applicationTestTime()
	request := validQuarantineRequest(t, now)

	workloads := &fakeWorkloadRepository{}

	incidents := &fakeIncidentRepository{
		incident: domain.Incident{
			ID:                17,
			WorkloadID:        request.WorkloadSPIFFEID,
			Status:            domain.IncidentStatusOpen,
			ScoreAtQuarantine: request.Score,
			QuarantinedAt:     now,
			CreatedAt:         now,
			UpdatedAt:         now,
		},
	}

	audits := &fakeAuditRepository{}

	service, err := NewQuarantineService(
		workloads,
		incidents,
		audits,
	)
	if err != nil {
		t.Fatalf(
			"NewQuarantineService() error: %v",
			err,
		)
	}

	result, err := service.Quarantine(
		context.Background(),
		request,
	)
	if err != nil {
		t.Fatalf(
			"Quarantine() error: %v",
			err,
		)
	}

	if result.Incident.ID != 17 {
		t.Fatalf(
			"incident ID = %d, want 17",
			result.Incident.ID,
		)
	}

	if workloads.quarantineCalls != 1 {
		t.Fatalf(
			"workload quarantine calls = %d, want 1",
			workloads.quarantineCalls,
		)
	}

	if workloads.releaseCalls != 0 {
		t.Fatalf(
			"workload release calls = %d, want 0",
			workloads.releaseCalls,
		)
	}

	if incidents.createCalls != 1 {
		t.Fatalf(
			"incident create calls = %d, want 1",
			incidents.createCalls,
		)
	}

	if len(result.AuditRecords) != 2 {
		t.Fatalf(
			"audit record count = %d, want 2",
			len(result.AuditRecords),
		)
	}

	if result.AuditRecords[0].Action !=
		domain.AuditActionWorkloadQuarantined {
		t.Fatalf(
			"first audit action = %q, want %q",
			result.AuditRecords[0].Action,
			domain.AuditActionWorkloadQuarantined,
		)
	}

	if result.AuditRecords[1].Action !=
		domain.AuditActionIncidentCreated {
		t.Fatalf(
			"second audit action = %q, want %q",
			result.AuditRecords[1].Action,
			domain.AuditActionIncidentCreated,
		)
	}

	var details map[string]any

	if err = json.Unmarshal(
		result.AuditRecords[1].DetailsJSON,
		&details,
	); err != nil {
		t.Fatalf(
			"json.Unmarshal() error: %v",
			err,
		)
	}

	if details["incident_id"] != float64(17) {
		t.Fatalf(
			"incident_id detail = %v, want 17",
			details["incident_id"],
		)
	}
}

func TestQuarantineServiceRejectsScoreBelowThreshold(
	t *testing.T,
) {
	now := applicationTestTime()
	request := validQuarantineRequest(t, now)
	request.Score = domain.QuarantineThreshold - 1

	workloads := &fakeWorkloadRepository{}
	incidents := &fakeIncidentRepository{}
	audits := &fakeAuditRepository{}

	service, err := NewQuarantineService(
		workloads,
		incidents,
		audits,
	)
	if err != nil {
		t.Fatalf(
			"NewQuarantineService() error: %v",
			err,
		)
	}

	_, err = service.Quarantine(
		context.Background(),
		request,
	)
	if err == nil ||
		!strings.Contains(
			err.Error(),
			"must be at least",
		) {
		t.Fatalf(
			"Quarantine() error = %v",
			err,
		)
	}

	if workloads.quarantineCalls != 0 {
		t.Fatalf(
			"workload quarantine calls = %d, want 0",
			workloads.quarantineCalls,
		)
	}

	if incidents.createCalls != 0 {
		t.Fatalf(
			"incident create calls = %d, want 0",
			incidents.createCalls,
		)
	}

	if audits.createCalls != 0 {
		t.Fatalf(
			"audit create calls = %d, want 0",
			audits.createCalls,
		)
	}
}

func TestQuarantineServiceRollsBackWorkloadWhenIncidentFails(
	t *testing.T,
) {
	now := applicationTestTime()
	request := validQuarantineRequest(t, now)

	incidentErr := errors.New(
		"incident storage unavailable",
	)

	workloads := &fakeWorkloadRepository{}

	incidents := &fakeIncidentRepository{
		createErr: incidentErr,
	}

	audits := &fakeAuditRepository{}

	service, err := NewQuarantineService(
		workloads,
		incidents,
		audits,
	)
	if err != nil {
		t.Fatalf(
			"NewQuarantineService() error: %v",
			err,
		)
	}

	_, err = service.Quarantine(
		context.Background(),
		request,
	)
	if !errors.Is(err, incidentErr) {
		t.Fatalf(
			"Quarantine() error = %v, want incident error",
			err,
		)
	}

	if workloads.quarantineCalls != 1 {
		t.Fatalf(
			"workload quarantine calls = %d, want 1",
			workloads.quarantineCalls,
		)
	}

	if workloads.releaseCalls != 1 {
		t.Fatalf(
			"workload release calls = %d, want 1",
			workloads.releaseCalls,
		)
	}

	if audits.createCalls != 0 {
		t.Fatalf(
			"audit create calls = %d, want 0",
			audits.createCalls,
		)
	}
}

func TestQuarantineServiceKeepsQuarantineWhenAuditFails(
	t *testing.T,
) {
	now := applicationTestTime()
	request := validQuarantineRequest(t, now)

	auditErr := errors.New(
		"audit storage unavailable",
	)

	workloads := &fakeWorkloadRepository{}

	incidents := &fakeIncidentRepository{
		incident: domain.Incident{
			ID:                23,
			WorkloadID:        request.WorkloadSPIFFEID,
			Status:            domain.IncidentStatusOpen,
			ScoreAtQuarantine: request.Score,
			QuarantinedAt:     now,
			CreatedAt:         now,
			UpdatedAt:         now,
		},
	}

	audits := &fakeAuditRepository{
		failAt:    1,
		createErr: auditErr,
	}

	service, err := NewQuarantineService(
		workloads,
		incidents,
		audits,
	)
	if err != nil {
		t.Fatalf(
			"NewQuarantineService() error: %v",
			err,
		)
	}

	result, err := service.Quarantine(
		context.Background(),
		request,
	)
	if !errors.Is(err, auditErr) {
		t.Fatalf(
			"Quarantine() error = %v, want audit error",
			err,
		)
	}

	if result.Incident.ID != 23 {
		t.Fatalf(
			"incident ID = %d, want 23",
			result.Incident.ID,
		)
	}

	if workloads.releaseCalls != 0 {
		t.Fatalf(
			"workload release calls = %d, want 0",
			workloads.releaseCalls,
		)
	}
}

func TestQuarantineServiceRejectsCancelledContext(
	t *testing.T,
) {
	now := applicationTestTime()
	request := validQuarantineRequest(t, now)

	workloads := &fakeWorkloadRepository{}
	incidents := &fakeIncidentRepository{}
	audits := &fakeAuditRepository{}

	service, err := NewQuarantineService(
		workloads,
		incidents,
		audits,
	)
	if err != nil {
		t.Fatalf(
			"NewQuarantineService() error: %v",
			err,
		)
	}

	ctx, cancel := context.WithCancel(
		context.Background(),
	)
	cancel()

	_, err = service.Quarantine(
		ctx,
		request,
	)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf(
			"Quarantine() error = %v, want context.Canceled",
			err,
		)
	}

	if workloads.quarantineCalls != 0 {
		t.Fatalf(
			"workload quarantine calls = %d, want 0",
			workloads.quarantineCalls,
		)
	}
}

func TestNewQuarantineServiceRejectsNilDependencies(
	t *testing.T,
) {
	workloads := &fakeWorkloadRepository{}
	incidents := &fakeIncidentRepository{}
	audits := &fakeAuditRepository{}

	tests := []struct {
		name      string
		workloads WorkloadRepository
		incidents IncidentRepository
		audits    AuditRepository
	}{
		{
			name:      "nil workload repository",
			workloads: nil,
			incidents: incidents,
			audits:    audits,
		},
		{
			name:      "nil incident repository",
			workloads: workloads,
			incidents: nil,
			audits:    audits,
		},
		{
			name:      "nil audit repository",
			workloads: workloads,
			incidents: incidents,
			audits:    nil,
		},
	}

	for _, test := range tests {
		t.Run(
			test.name,
			func(t *testing.T) {
				service, err := NewQuarantineService(
					test.workloads,
					test.incidents,
					test.audits,
				)

				if err == nil {
					t.Fatal(
						"NewQuarantineService() returned nil error",
					)
				}

				if service != nil {
					t.Fatal(
						"NewQuarantineService() returned non-nil service",
					)
				}
			},
		)
	}
}

type fakeWorkloadRepository struct {
	quarantineCalls int
	releaseCalls    int
	quarantineErr   error
	releaseErr      error
}

func (f *fakeWorkloadRepository) Quarantine(
	_ context.Context,
	_ string,
	_ int,
	_ time.Time,
) error {
	f.quarantineCalls++

	return f.quarantineErr
}

func (f *fakeWorkloadRepository) Release(
	_ context.Context,
	_ string,
	_ time.Time,
) error {
	f.releaseCalls++

	return f.releaseErr
}

type fakeIncidentRepository struct {
	createCalls int
	incident    domain.Incident
	createErr   error
}

func (f *fakeIncidentRepository) Create(
	_ context.Context,
	_ string,
	_ int,
	_ []domain.RiskContribution,
	_ time.Time,
) (domain.Incident, error) {
	f.createCalls++

	if f.createErr != nil {
		return domain.Incident{}, f.createErr
	}

	return f.incident, nil
}

type fakeAuditRepository struct {
	createCalls int
	failAt      int
	createErr   error
	records     []domain.AuditRecord
}

func (f *fakeAuditRepository) Create(
	_ context.Context,
	record domain.AuditRecord,
) (domain.AuditRecord, error) {
	f.createCalls++

	if f.failAt == f.createCalls {
		return domain.AuditRecord{}, f.createErr
	}

	record.ID = int64(f.createCalls)

	f.records = append(
		f.records,
		record,
	)

	return record, nil
}

func validQuarantineRequest(
	t *testing.T,
	now time.Time,
) QuarantineRequest {
	t.Helper()

	return QuarantineRequest{
		WorkloadSPIFFEID: domain.SPIFFEIDReportClient,
		ActorSPIFFEID:    domain.SPIFFEIDDemoctl,
		Score:            domain.QuarantineThreshold + 20,
		Reasons: []domain.RiskContribution{
			validRiskContribution(t),
		},
		OccurredAt: now,
	}
}

func validRiskContribution(
	t *testing.T,
) domain.RiskContribution {
	t.Helper()

	for points := 1; points <= 200; points++ {
		contribution := domain.RiskContribution{
			Rule:   domain.RiskRuleHighlySensitive,
			Points: points,
			Reason: "attempted access to /api/payment-details",
		}

		if err := contribution.Validate(); err == nil {
			return contribution
		}
	}

	t.Fatal(
		"could not construct a valid risk contribution",
	)

	return domain.RiskContribution{}
}

func applicationTestTime() time.Time {
	return time.Date(
		2026,
		time.June,
		20,
		10,
		0,
		0,
		0,
		time.UTC,
	)
}
