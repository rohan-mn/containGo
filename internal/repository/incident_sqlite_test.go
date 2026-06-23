package repository

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"containgo.local/containgo/internal/domain"
	"containgo.local/containgo/internal/testutil"
)

func TestSQLiteIncidentRepositoryLifecycle(
	t *testing.T,
) {
	db := testutil.OpenSQLite(t)
	seedWorkloads(t, db)

	workloadRepository, err :=
		NewSQLiteWorkloadRepository(db)
	if err != nil {
		t.Fatalf(
			"NewSQLiteWorkloadRepository() error: %v",
			err,
		)
	}

	incidentRepository, err :=
		NewSQLiteIncidentRepository(db)
	if err != nil {
		t.Fatalf(
			"NewSQLiteIncidentRepository() error: %v",
			err,
		)
	}

	ctx := context.Background()
	quarantinedAt := repositoryTestTime()

	err = workloadRepository.Quarantine(
		ctx,
		domain.SPIFFEIDReportClient,
		120,
		quarantinedAt,
	)
	if err != nil {
		t.Fatalf(
			"Quarantine() error: %v",
			err,
		)
	}

	reasons := []domain.RiskContribution{
		mustContribution(
			t,
			domain.RiskRuleUnauthorizedEndpoint,
			"workload is not authorized for the requested endpoint",
		),
		mustContribution(
			t,
			domain.RiskRuleHighlySensitive,
			"attempted access to /api/payment-details",
		),
	}

	incident, err := incidentRepository.Create(
		ctx,
		domain.SPIFFEIDReportClient,
		120,
		reasons,
		quarantinedAt,
	)
	if err != nil {
		t.Fatalf(
			"Create() error: %v",
			err,
		)
	}

	if !incident.IsOpen() {
		t.Fatal(
			"created incident is not open",
		)
	}

	if incident.ScoreAtQuarantine != 120 {
		t.Fatalf(
			"score = %d, want 120",
			incident.ScoreAtQuarantine,
		)
	}

	if len(incident.Reasons) != 2 {
		t.Fatalf(
			"reason count = %d, want 2",
			len(incident.Reasons),
		)
	}

	if incident.TotalReasonPoints() != 65 {
		t.Fatalf(
			"reason points = %d, want 65",
			incident.TotalReasonPoints(),
		)
	}

	openIncident, err :=
		incidentRepository.FindOpenByWorkload(
			ctx,
			domain.SPIFFEIDReportClient,
		)
	if err != nil {
		t.Fatalf(
			"FindOpenByWorkload() error: %v",
			err,
		)
	}

	if openIncident.ID != incident.ID {
		t.Fatalf(
			"open incident ID = %d, want %d",
			openIncident.ID,
			incident.ID,
		)
	}

	releasedAt := quarantinedAt.Add(
		time.Minute,
	)

	released, err := incidentRepository.Release(
		ctx,
		domain.SPIFFEIDReportClient,
		domain.SPIFFEIDDemoctl,
		releasedAt,
	)
	if err != nil {
		t.Fatalf(
			"Release() error: %v",
			err,
		)
	}

	if released.IsOpen() {
		t.Fatal(
			"released incident still reports open",
		)
	}

	if released.Status !=
		domain.IncidentStatusReleased {
		t.Fatalf(
			"released status = %q, want released",
			released.Status,
		)
	}

	if released.ReleasedAt == nil ||
		!released.ReleasedAt.Equal(releasedAt) {
		t.Fatalf(
			"released timestamp = %v, want %v",
			released.ReleasedAt,
			releasedAt,
		)
	}

	if released.ReleasedBy !=
		domain.SPIFFEIDDemoctl {
		t.Fatalf(
			"released by = %q, want %q",
			released.ReleasedBy,
			domain.SPIFFEIDDemoctl,
		)
	}

	_, err = incidentRepository.FindOpenByWorkload(
		ctx,
		domain.SPIFFEIDReportClient,
	)

	if !errors.Is(err, ErrNotFound) {
		t.Fatalf(
			"FindOpenByWorkload() after release error = %v, want ErrNotFound",
			err,
		)
	}

	history, err :=
		incidentRepository.ListByWorkload(
			ctx,
			domain.SPIFFEIDReportClient,
			10,
		)
	if err != nil {
		t.Fatalf(
			"ListByWorkload() error: %v",
			err,
		)
	}

	if len(history) != 1 {
		t.Fatalf(
			"history count = %d, want 1",
			len(history),
		)
	}

	if history[0].Status !=
		domain.IncidentStatusReleased {
		t.Fatalf(
			"historical status = %q, want released",
			history[0].Status,
		)
	}
}

func TestSQLiteIncidentRepositoryRejectsSecondOpenIncident(
	t *testing.T,
) {
	db := testutil.OpenSQLite(t)
	seedWorkloads(t, db)

	workloadRepository, err :=
		NewSQLiteWorkloadRepository(db)
	if err != nil {
		t.Fatalf(
			"NewSQLiteWorkloadRepository() error: %v",
			err,
		)
	}

	incidentRepository, err :=
		NewSQLiteIncidentRepository(db)
	if err != nil {
		t.Fatalf(
			"NewSQLiteIncidentRepository() error: %v",
			err,
		)
	}

	ctx := context.Background()
	now := repositoryTestTime()

	err = workloadRepository.Quarantine(
		ctx,
		domain.SPIFFEIDReportClient,
		95,
		now,
	)
	if err != nil {
		t.Fatalf(
			"Quarantine() error: %v",
			err,
		)
	}

	reasons := []domain.RiskContribution{
		mustContribution(
			t,
			domain.RiskRuleAdministrative,
			"attempted access to /api/admin/config",
		),
	}

	_, err = incidentRepository.Create(
		ctx,
		domain.SPIFFEIDReportClient,
		95,
		reasons,
		now,
	)
	if err != nil {
		t.Fatalf(
			"first Create() error: %v",
			err,
		)
	}

	_, err = incidentRepository.Create(
		ctx,
		domain.SPIFFEIDReportClient,
		95,
		reasons,
		now.Add(time.Second),
	)

	if !errors.Is(err, ErrConflict) {
		t.Fatalf(
			"second Create() error = %v, want ErrConflict",
			err,
		)
	}
}

func TestSQLiteIncidentRepositoryInvalidState(
	t *testing.T,
) {
	db := testutil.OpenSQLite(t)
	seedWorkloads(t, db)

	incidentRepository, err :=
		NewSQLiteIncidentRepository(db)
	if err != nil {
		t.Fatalf(
			"NewSQLiteIncidentRepository() error: %v",
			err,
		)
	}

	ctx := context.Background()
	now := repositoryTestTime()

	reasons := []domain.RiskContribution{
		mustContribution(
			t,
			domain.RiskRuleSensitiveEndpoint,
			"attempted access to /api/customers",
		),
	}

	_, err = incidentRepository.Create(
		ctx,
		domain.SPIFFEIDOrderClient,
		80,
		reasons,
		now,
	)

	if !errors.Is(err, ErrInvalidState) {
		t.Fatalf(
			"Create(active workload) error = %v, want ErrInvalidState",
			err,
		)
	}

	_, err = incidentRepository.Create(
		ctx,
		domain.SPIFFEIDReportClient,
		69,
		reasons,
		now,
	)

	if err == nil ||
		!strings.Contains(
			err.Error(),
			"must be at least 70",
		) {
		t.Fatalf(
			"Create(score 69) error = %v",
			err,
		)
	}

	_, err = incidentRepository.Create(
		ctx,
		domain.SPIFFEIDReportClient,
		80,
		nil,
		now,
	)

	if err == nil ||
		!strings.Contains(
			err.Error(),
			"at least one reason",
		) {
		t.Fatalf(
			"Create(no reasons) error = %v",
			err,
		)
	}

	_, err = incidentRepository.Release(
		ctx,
		domain.SPIFFEIDReportClient,
		domain.SPIFFEIDDemoctl,
		now,
	)

	if !errors.Is(err, ErrNotFound) {
		t.Fatalf(
			"Release(no open incident) error = %v, want ErrNotFound",
			err,
		)
	}
}

func TestSQLiteIncidentRepositoryPreservesHistory(
	t *testing.T,
) {
	db := testutil.OpenSQLite(t)
	seedWorkloads(t, db)

	workloadRepository, err :=
		NewSQLiteWorkloadRepository(db)
	if err != nil {
		t.Fatalf(
			"NewSQLiteWorkloadRepository() error: %v",
			err,
		)
	}

	incidentRepository, err :=
		NewSQLiteIncidentRepository(db)
	if err != nil {
		t.Fatalf(
			"NewSQLiteIncidentRepository() error: %v",
			err,
		)
	}

	ctx := context.Background()
	start := repositoryTestTime()

	firstReasons := []domain.RiskContribution{
		mustContribution(
			t,
			domain.RiskRuleHighlySensitive,
			"attempted access to /api/payment-details",
		),
	}

	err = workloadRepository.Quarantine(
		ctx,
		domain.SPIFFEIDReportClient,
		90,
		start,
	)
	if err != nil {
		t.Fatalf(
			"first Quarantine() error: %v",
			err,
		)
	}

	first, err := incidentRepository.Create(
		ctx,
		domain.SPIFFEIDReportClient,
		90,
		firstReasons,
		start,
	)
	if err != nil {
		t.Fatalf(
			"first Create() error: %v",
			err,
		)
	}

	releaseTime := start.Add(time.Minute)

	_, err = incidentRepository.Release(
		ctx,
		domain.SPIFFEIDReportClient,
		domain.SPIFFEIDDemoctl,
		releaseTime,
	)
	if err != nil {
		t.Fatalf(
			"first incident Release() error: %v",
			err,
		)
	}

	err = workloadRepository.Release(
		ctx,
		domain.SPIFFEIDReportClient,
		releaseTime,
	)
	if err != nil {
		t.Fatalf(
			"workload Release() error: %v",
			err,
		)
	}

	secondTime := start.Add(
		2 * time.Minute,
	)

	err = workloadRepository.Quarantine(
		ctx,
		domain.SPIFFEIDReportClient,
		110,
		secondTime,
	)
	if err != nil {
		t.Fatalf(
			"second Quarantine() error: %v",
			err,
		)
	}

	secondReasons := []domain.RiskContribution{
		mustContribution(
			t,
			domain.RiskRuleAdministrative,
			"attempted access to /api/admin/config",
		),
	}

	second, err := incidentRepository.Create(
		ctx,
		domain.SPIFFEIDReportClient,
		110,
		secondReasons,
		secondTime,
	)
	if err != nil {
		t.Fatalf(
			"second Create() error: %v",
			err,
		)
	}

	history, err :=
		incidentRepository.ListByWorkload(
			ctx,
			domain.SPIFFEIDReportClient,
			10,
		)
	if err != nil {
		t.Fatalf(
			"ListByWorkload() error: %v",
			err,
		)
	}

	if len(history) != 2 {
		t.Fatalf(
			"history count = %d, want 2",
			len(history),
		)
	}

	if history[0].ID != second.ID {
		t.Fatalf(
			"newest incident ID = %d, want %d",
			history[0].ID,
			second.ID,
		)
	}

	if history[1].ID != first.ID {
		t.Fatalf(
			"oldest incident ID = %d, want %d",
			history[1].ID,
			first.ID,
		)
	}

	if history[0].Status !=
		domain.IncidentStatusOpen {
		t.Fatalf(
			"newest status = %q, want open",
			history[0].Status,
		)
	}

	if history[1].Status !=
		domain.IncidentStatusReleased {
		t.Fatalf(
			"oldest status = %q, want released",
			history[1].Status,
		)
	}
}
