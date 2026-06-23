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

func TestReleaseServiceSuccess(
	t *testing.T,
) {
	now := releaseTestTime()
	request := validReleaseRequest(now)

	openIncident := releaseTestOpenIncident(
		request.WorkloadSPIFFEID,
		now,
	)

	releasedIncident := openIncident
	releasedIncident.Status =
		domain.IncidentStatusReleased
	releasedIncident.ReleasedAt = &now
	releasedIncident.ReleasedBy =
		request.ActorSPIFFEID
	releasedIncident.UpdatedAt = now

	workloads := &releaseWorkloadRepositoryFake{}

	incidents := &releaseIncidentRepositoryFake{
		openIncident:     openIncident,
		releasedIncident: releasedIncident,
	}

	audits := &releaseAuditRepositoryFake{}

	service, err := NewReleaseService(
		workloads,
		incidents,
		audits,
	)
	if err != nil {
		t.Fatalf(
			"NewReleaseService() error: %v",
			err,
		)
	}

	result, err := service.Release(
		context.Background(),
		request,
	)
	if err != nil {
		t.Fatalf(
			"Release() error: %v",
			err,
		)
	}

	if result.Incident.Status !=
		domain.IncidentStatusReleased {
		t.Fatalf(
			"incident status = %q, want released",
			result.Incident.Status,
		)
	}

	if workloads.releaseCalls != 1 {
		t.Fatalf(
			"workload release calls = %d, want 1",
			workloads.releaseCalls,
		)
	}

	if workloads.quarantineCalls != 0 {
		t.Fatalf(
			"workload quarantine calls = %d, want 0",
			workloads.quarantineCalls,
		)
	}

	if incidents.findCalls != 1 {
		t.Fatalf(
			"incident find calls = %d, want 1",
			incidents.findCalls,
		)
	}

	if incidents.releaseCalls != 1 {
		t.Fatalf(
			"incident release calls = %d, want 1",
			incidents.releaseCalls,
		)
	}

	if len(result.AuditRecords) != 2 {
		t.Fatalf(
			"audit record count = %d, want 2",
			len(result.AuditRecords),
		)
	}

	if result.AuditRecords[0].Action !=
		domain.AuditActionIncidentReleased {
		t.Fatalf(
			"first audit action = %q, want %q",
			result.AuditRecords[0].Action,
			domain.AuditActionIncidentReleased,
		)
	}

	if result.AuditRecords[1].Action !=
		domain.AuditActionWorkloadReleased {
		t.Fatalf(
			"second audit action = %q, want %q",
			result.AuditRecords[1].Action,
			domain.AuditActionWorkloadReleased,
		)
	}

	var details map[string]any

	if err = json.Unmarshal(
		result.AuditRecords[0].DetailsJSON,
		&details,
	); err != nil {
		t.Fatalf(
			"json.Unmarshal() error: %v",
			err,
		)
	}

	if details["incident_id"] !=
		float64(openIncident.ID) {
		t.Fatalf(
			"incident_id detail = %v, want %d",
			details["incident_id"],
			openIncident.ID,
		)
	}
}

func TestReleaseServiceStopsWhenNoOpenIncident(
	t *testing.T,
) {
	now := releaseTestTime()
	request := validReleaseRequest(now)

	findErr := errors.New(
		"open incident not found",
	)

	workloads := &releaseWorkloadRepositoryFake{}

	incidents := &releaseIncidentRepositoryFake{
		findErr: findErr,
	}

	audits := &releaseAuditRepositoryFake{}

	service, err := NewReleaseService(
		workloads,
		incidents,
		audits,
	)
	if err != nil {
		t.Fatalf(
			"NewReleaseService() error: %v",
			err,
		)
	}

	_, err = service.Release(
		context.Background(),
		request,
	)
	if !errors.Is(err, findErr) {
		t.Fatalf(
			"Release() error = %v, want find error",
			err,
		)
	}

	if workloads.releaseCalls != 0 {
		t.Fatalf(
			"workload release calls = %d, want 0",
			workloads.releaseCalls,
		)
	}

	if incidents.releaseCalls != 0 {
		t.Fatalf(
			"incident release calls = %d, want 0",
			incidents.releaseCalls,
		)
	}

	if audits.createCalls != 0 {
		t.Fatalf(
			"audit create calls = %d, want 0",
			audits.createCalls,
		)
	}
}

func TestReleaseServiceStopsWhenWorkloadReleaseFails(
	t *testing.T,
) {
	now := releaseTestTime()
	request := validReleaseRequest(now)

	releaseErr := errors.New(
		"workload release failed",
	)

	workloads := &releaseWorkloadRepositoryFake{
		releaseErr: releaseErr,
	}

	incidents := &releaseIncidentRepositoryFake{
		openIncident: releaseTestOpenIncident(
			request.WorkloadSPIFFEID,
			now,
		),
	}

	audits := &releaseAuditRepositoryFake{}

	service, err := NewReleaseService(
		workloads,
		incidents,
		audits,
	)
	if err != nil {
		t.Fatalf(
			"NewReleaseService() error: %v",
			err,
		)
	}

	_, err = service.Release(
		context.Background(),
		request,
	)
	if !errors.Is(err, releaseErr) {
		t.Fatalf(
			"Release() error = %v, want workload release error",
			err,
		)
	}

	if incidents.releaseCalls != 0 {
		t.Fatalf(
			"incident release calls = %d, want 0",
			incidents.releaseCalls,
		)
	}

	if audits.createCalls != 0 {
		t.Fatalf(
			"audit create calls = %d, want 0",
			audits.createCalls,
		)
	}
}

func TestReleaseServiceRestoresQuarantineWhenIncidentReleaseFails(
	t *testing.T,
) {
	now := releaseTestTime()
	request := validReleaseRequest(now)

	incidentReleaseErr := errors.New(
		"incident release failed",
	)

	openIncident := releaseTestOpenIncident(
		request.WorkloadSPIFFEID,
		now,
	)

	workloads := &releaseWorkloadRepositoryFake{}

	incidents := &releaseIncidentRepositoryFake{
		openIncident: openIncident,
		releaseErr:   incidentReleaseErr,
	}

	audits := &releaseAuditRepositoryFake{}

	service, err := NewReleaseService(
		workloads,
		incidents,
		audits,
	)
	if err != nil {
		t.Fatalf(
			"NewReleaseService() error: %v",
			err,
		)
	}

	_, err = service.Release(
		context.Background(),
		request,
	)
	if !errors.Is(err, incidentReleaseErr) {
		t.Fatalf(
			"Release() error = %v, want incident release error",
			err,
		)
	}

	if workloads.releaseCalls != 1 {
		t.Fatalf(
			"workload release calls = %d, want 1",
			workloads.releaseCalls,
		)
	}

	if workloads.quarantineCalls != 1 {
		t.Fatalf(
			"workload quarantine calls = %d, want 1",
			workloads.quarantineCalls,
		)
	}

	if workloads.lastQuarantineScore !=
		openIncident.ScoreAtQuarantine {
		t.Fatalf(
			"restored quarantine score = %d, want %d",
			workloads.lastQuarantineScore,
			openIncident.ScoreAtQuarantine,
		)
	}

	if audits.createCalls != 0 {
		t.Fatalf(
			"audit create calls = %d, want 0",
			audits.createCalls,
		)
	}
}

func TestReleaseServiceReportsCompensationFailure(
	t *testing.T,
) {
	now := releaseTestTime()
	request := validReleaseRequest(now)

	incidentReleaseErr := errors.New(
		"incident release failed",
	)
	compensationErr := errors.New(
		"quarantine restoration failed",
	)

	workloads := &releaseWorkloadRepositoryFake{
		quarantineErr: compensationErr,
	}

	incidents := &releaseIncidentRepositoryFake{
		openIncident: releaseTestOpenIncident(
			request.WorkloadSPIFFEID,
			now,
		),
		releaseErr: incidentReleaseErr,
	}

	service, err := NewReleaseService(
		workloads,
		incidents,
		&releaseAuditRepositoryFake{},
	)
	if err != nil {
		t.Fatalf(
			"NewReleaseService() error: %v",
			err,
		)
	}

	_, err = service.Release(
		context.Background(),
		request,
	)

	if !errors.Is(err, incidentReleaseErr) {
		t.Fatalf(
			"Release() error = %v, want incident error",
			err,
		)
	}

	if !errors.Is(err, compensationErr) {
		t.Fatalf(
			"Release() error = %v, want compensation error",
			err,
		)
	}

	if workloads.quarantineCalls != 1 {
		t.Fatalf(
			"workload quarantine calls = %d, want 1",
			workloads.quarantineCalls,
		)
	}
}

func TestReleaseServiceKeepsReleasedStateWhenAuditFails(
	t *testing.T,
) {
	now := releaseTestTime()
	request := validReleaseRequest(now)

	auditErr := errors.New(
		"audit storage unavailable",
	)

	openIncident := releaseTestOpenIncident(
		request.WorkloadSPIFFEID,
		now,
	)

	releasedIncident := openIncident
	releasedIncident.Status =
		domain.IncidentStatusReleased
	releasedIncident.ReleasedAt = &now
	releasedIncident.ReleasedBy =
		request.ActorSPIFFEID

	workloads := &releaseWorkloadRepositoryFake{}

	incidents := &releaseIncidentRepositoryFake{
		openIncident:     openIncident,
		releasedIncident: releasedIncident,
	}

	audits := &releaseAuditRepositoryFake{
		failAt:    1,
		createErr: auditErr,
	}

	service, err := NewReleaseService(
		workloads,
		incidents,
		audits,
	)
	if err != nil {
		t.Fatalf(
			"NewReleaseService() error: %v",
			err,
		)
	}

	result, err := service.Release(
		context.Background(),
		request,
	)
	if !errors.Is(err, auditErr) {
		t.Fatalf(
			"Release() error = %v, want audit error",
			err,
		)
	}

	if result.Incident.Status !=
		domain.IncidentStatusReleased {
		t.Fatalf(
			"incident status = %q, want released",
			result.Incident.Status,
		)
	}

	if workloads.quarantineCalls != 0 {
		t.Fatalf(
			"workload quarantine calls = %d, want 0",
			workloads.quarantineCalls,
		)
	}
}

func TestReleaseServiceRejectsInvalidRequest(
	t *testing.T,
) {
	now := releaseTestTime()

	tests := []struct {
		name          string
		request       ReleaseRequest
		errorContains string
	}{
		{
			name: "unknown workload",
			request: ReleaseRequest{
				WorkloadSPIFFEID: "spiffe://containgo.local/unknown",
				ActorSPIFFEID:    domain.SPIFFEIDDemoctl,
				OccurredAt:       now,
			},
			errorContains: "unknown workload",
		},
		{
			name: "unknown actor",
			request: ReleaseRequest{
				WorkloadSPIFFEID: domain.SPIFFEIDReportClient,
				ActorSPIFFEID:    "spiffe://containgo.local/unknown",
				OccurredAt:       now,
			},
			errorContains: "unknown release actor",
		},
		{
			name: "zero timestamp",
			request: ReleaseRequest{
				WorkloadSPIFFEID: domain.SPIFFEIDReportClient,
				ActorSPIFFEID:    domain.SPIFFEIDDemoctl,
			},
			errorContains: "must not be zero",
		},
	}

	for _, test := range tests {
		t.Run(
			test.name,
			func(t *testing.T) {
				workloads :=
					&releaseWorkloadRepositoryFake{}
				incidents :=
					&releaseIncidentRepositoryFake{}
				audits :=
					&releaseAuditRepositoryFake{}

				service, err := NewReleaseService(
					workloads,
					incidents,
					audits,
				)
				if err != nil {
					t.Fatalf(
						"NewReleaseService() error: %v",
						err,
					)
				}

				_, err = service.Release(
					context.Background(),
					test.request,
				)

				if err == nil ||
					!strings.Contains(
						err.Error(),
						test.errorContains,
					) {
					t.Fatalf(
						"Release() error = %v, want text %q",
						err,
						test.errorContains,
					)
				}

				if incidents.findCalls != 0 {
					t.Fatalf(
						"incident find calls = %d, want 0",
						incidents.findCalls,
					)
				}
			},
		)
	}
}

func TestReleaseServiceRejectsCancelledContext(
	t *testing.T,
) {
	now := releaseTestTime()
	request := validReleaseRequest(now)

	service, err := NewReleaseService(
		&releaseWorkloadRepositoryFake{},
		&releaseIncidentRepositoryFake{},
		&releaseAuditRepositoryFake{},
	)
	if err != nil {
		t.Fatalf(
			"NewReleaseService() error: %v",
			err,
		)
	}

	ctx, cancel := context.WithCancel(
		context.Background(),
	)
	cancel()

	_, err = service.Release(
		ctx,
		request,
	)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf(
			"Release() error = %v, want context.Canceled",
			err,
		)
	}
}

func TestNewReleaseServiceRejectsNilDependencies(
	t *testing.T,
) {
	workloads := &releaseWorkloadRepositoryFake{}
	incidents := &releaseIncidentRepositoryFake{}
	audits := &releaseAuditRepositoryFake{}

	tests := []struct {
		name      string
		workloads WorkloadRepository
		incidents IncidentReleaseRepository
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
				service, err := NewReleaseService(
					test.workloads,
					test.incidents,
					test.audits,
				)

				if err == nil {
					t.Fatal(
						"NewReleaseService() returned nil error",
					)
				}

				if service != nil {
					t.Fatal(
						"NewReleaseService() returned non-nil service",
					)
				}
			},
		)
	}
}

type releaseWorkloadRepositoryFake struct {
	releaseCalls        int
	quarantineCalls     int
	releaseErr          error
	quarantineErr       error
	lastQuarantineScore int
	lastQuarantineAt    time.Time
}

func (f *releaseWorkloadRepositoryFake) Quarantine(
	_ context.Context,
	_ string,
	score int,
	quarantinedAt time.Time,
) error {
	f.quarantineCalls++
	f.lastQuarantineScore = score
	f.lastQuarantineAt = quarantinedAt

	return f.quarantineErr
}

func (f *releaseWorkloadRepositoryFake) Release(
	_ context.Context,
	_ string,
	_ time.Time,
) error {
	f.releaseCalls++

	return f.releaseErr
}

type releaseIncidentRepositoryFake struct {
	findCalls        int
	releaseCalls     int
	openIncident     domain.Incident
	releasedIncident domain.Incident
	findErr          error
	releaseErr       error
}

func (f *releaseIncidentRepositoryFake) FindOpenByWorkload(
	_ context.Context,
	_ string,
) (domain.Incident, error) {
	f.findCalls++

	if f.findErr != nil {
		return domain.Incident{}, f.findErr
	}

	return f.openIncident, nil
}

func (f *releaseIncidentRepositoryFake) Release(
	_ context.Context,
	_ string,
	_ string,
	_ time.Time,
) (domain.Incident, error) {
	f.releaseCalls++

	if f.releaseErr != nil {
		return domain.Incident{}, f.releaseErr
	}

	return f.releasedIncident, nil
}

type releaseAuditRepositoryFake struct {
	createCalls int
	failAt      int
	createErr   error
	records     []domain.AuditRecord
}

func (f *releaseAuditRepositoryFake) Create(
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

func validReleaseRequest(
	now time.Time,
) ReleaseRequest {
	return ReleaseRequest{
		WorkloadSPIFFEID: domain.SPIFFEIDReportClient,
		ActorSPIFFEID:    domain.SPIFFEIDDemoctl,
		OccurredAt:       now,
	}
}

func releaseTestOpenIncident(
	workloadSPIFFEID string,
	now time.Time,
) domain.Incident {
	return domain.Incident{
		ID:                31,
		WorkloadID:        workloadSPIFFEID,
		Status:            domain.IncidentStatusOpen,
		ScoreAtQuarantine: domain.QuarantineThreshold + 20,
		QuarantinedAt:     now.Add(-time.Minute),
		CreatedAt:         now.Add(-time.Minute),
		UpdatedAt:         now.Add(-time.Minute),
	}
}

func releaseTestTime() time.Time {
	return time.Date(
		2026,
		time.June,
		21,
		10,
		0,
		0,
		0,
		time.UTC,
	)
}
