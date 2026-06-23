package repository

import (
	"context"
	"database/sql"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"containgo.local/containgo/internal/domain"
	"containgo.local/containgo/internal/testutil"
)

func TestSQLiteWorkloadRepositoryEnsureKnown(
	t *testing.T,
) {
	db := testutil.OpenSQLite(t)

	repository, err := NewSQLiteWorkloadRepository(
		db,
	)
	if err != nil {
		t.Fatalf(
			"NewSQLiteWorkloadRepository() unexpected error: %v",
			err,
		)
	}

	now := testTime()

	err = repository.EnsureKnown(
		context.Background(),
		now,
	)
	if err != nil {
		t.Fatalf(
			"EnsureKnown() unexpected error: %v",
			err,
		)
	}

	// Seeding must be idempotent.
	err = repository.EnsureKnown(
		context.Background(),
		now.Add(time.Minute),
	)
	if err != nil {
		t.Fatalf(
			"second EnsureKnown() unexpected error: %v",
			err,
		)
	}

	workloads, err := repository.List(
		context.Background(),
	)
	if err != nil {
		t.Fatalf(
			"List() unexpected error: %v",
			err,
		)
	}

	if len(workloads) != len(
		domain.KnownWorkloadIDs(),
	) {
		t.Fatalf(
			"workload count = %d, want %d",
			len(workloads),
			len(domain.KnownWorkloadIDs()),
		)
	}

	gotNames := make(
		[]string,
		0,
		len(workloads),
	)

	for _, workload := range workloads {
		gotNames = append(
			gotNames,
			workload.Name,
		)

		if workload.Status != domain.WorkloadStatusActive {
			t.Fatalf(
				"workload %q status = %q, want active",
				workload.Name,
				workload.Status,
			)
		}

		if workload.RiskScore != 0 {
			t.Fatalf(
				"workload %q score = %d, want 0",
				workload.Name,
				workload.RiskScore,
			)
		}
	}

	wantNames := []string{
		domain.WorkloadNameAPIGateway,
		domain.WorkloadNameControlPlane,
		domain.WorkloadNameDashboard,
		domain.WorkloadNameDemoctl,
		domain.WorkloadNameOrderClient,
		domain.WorkloadNameProtectedAPI,
		domain.WorkloadNameReportClient,
	}
	slices.Sort(wantNames)

	if !slices.Equal(
		gotNames,
		wantNames,
	) {
		t.Fatalf(
			"workload names = %v, want %v",
			gotNames,
			wantNames,
		)
	}
}

func TestSQLiteWorkloadRepositoryRiskLifecycle(
	t *testing.T,
) {
	db := testutil.OpenSQLite(t)

	repository := newSeededWorkloadRepository(
		t,
		db,
	)

	ctx := context.Background()
	initialTime := testTime()
	lastSeenAt := initialTime.Add(time.Minute)

	err := repository.UpdateRisk(
		ctx,
		domain.SPIFFEIDReportClient,
		65,
		1,
		lastSeenAt,
	)
	if err != nil {
		t.Fatalf(
			"UpdateRisk() unexpected error: %v",
			err,
		)
	}

	workload, err := repository.FindBySPIFFEID(
		ctx,
		domain.SPIFFEIDReportClient,
	)
	if err != nil {
		t.Fatalf(
			"FindBySPIFFEID() unexpected error: %v",
			err,
		)
	}

	if workload.RiskScore != 65 {
		t.Fatalf(
			"risk score = %d, want 65",
			workload.RiskScore,
		)
	}

	if workload.DeniedRequests != 1 {
		t.Fatalf(
			"denied requests = %d, want 1",
			workload.DeniedRequests,
		)
	}

	if workload.LastSeenAt == nil ||
		!workload.LastSeenAt.Equal(lastSeenAt) {
		t.Fatalf(
			"last seen = %v, want %v",
			workload.LastSeenAt,
			lastSeenAt,
		)
	}

	quarantinedAt := initialTime.Add(
		2 * time.Minute,
	)

	err = repository.Quarantine(
		ctx,
		domain.SPIFFEIDReportClient,
		120,
		quarantinedAt,
	)
	if err != nil {
		t.Fatalf(
			"Quarantine() unexpected error: %v",
			err,
		)
	}

	workload, err = repository.FindBySPIFFEID(
		ctx,
		domain.SPIFFEIDReportClient,
	)
	if err != nil {
		t.Fatalf(
			"FindBySPIFFEID() after quarantine: %v",
			err,
		)
	}

	if !workload.IsQuarantined() {
		t.Fatal(
			"workload was not marked quarantined",
		)
	}

	if workload.RiskScore != 120 {
		t.Fatalf(
			"quarantined score = %d, want 120",
			workload.RiskScore,
		)
	}

	if workload.QuarantinedAt == nil ||
		!workload.QuarantinedAt.Equal(
			quarantinedAt,
		) {
		t.Fatalf(
			"quarantined timestamp = %v, want %v",
			workload.QuarantinedAt,
			quarantinedAt,
		)
	}

	releasedAt := initialTime.Add(
		3 * time.Minute,
	)

	err = repository.Release(
		ctx,
		domain.SPIFFEIDReportClient,
		releasedAt,
	)
	if err != nil {
		t.Fatalf(
			"Release() unexpected error: %v",
			err,
		)
	}

	workload, err = repository.FindBySPIFFEID(
		ctx,
		domain.SPIFFEIDReportClient,
	)
	if err != nil {
		t.Fatalf(
			"FindBySPIFFEID() after release: %v",
			err,
		)
	}

	if workload.Status != domain.WorkloadStatusActive {
		t.Fatalf(
			"released status = %q, want active",
			workload.Status,
		)
	}

	if workload.RiskScore != 0 {
		t.Fatalf(
			"released score = %d, want 0",
			workload.RiskScore,
		)
	}

	if workload.DeniedRequests != 0 {
		t.Fatalf(
			"released denied count = %d, want 0",
			workload.DeniedRequests,
		)
	}

	if workload.QuarantinedAt != nil {
		t.Fatalf(
			"released quarantine timestamp = %v, want nil",
			workload.QuarantinedAt,
		)
	}
}

func TestSQLiteWorkloadRepositoryResetRisk(
	t *testing.T,
) {
	db := testutil.OpenSQLite(t)

	repository := newSeededWorkloadRepository(
		t,
		db,
	)

	ctx := context.Background()
	now := testTime()

	err := repository.UpdateRisk(
		ctx,
		domain.SPIFFEIDOrderClient,
		45,
		2,
		now.Add(time.Minute),
	)
	if err != nil {
		t.Fatalf(
			"UpdateRisk() unexpected error: %v",
			err,
		)
	}

	err = repository.ResetRisk(
		ctx,
		domain.SPIFFEIDOrderClient,
		now.Add(2*time.Minute),
	)
	if err != nil {
		t.Fatalf(
			"ResetRisk() unexpected error: %v",
			err,
		)
	}

	workload, err := repository.FindBySPIFFEID(
		ctx,
		domain.SPIFFEIDOrderClient,
	)
	if err != nil {
		t.Fatalf(
			"FindBySPIFFEID() unexpected error: %v",
			err,
		)
	}

	if workload.RiskScore != 0 {
		t.Fatalf(
			"reset score = %d, want 0",
			workload.RiskScore,
		)
	}

	if workload.DeniedRequests != 0 {
		t.Fatalf(
			"reset denied requests = %d, want 0",
			workload.DeniedRequests,
		)
	}
}

func TestSQLiteWorkloadRepositoryInvalidStates(
	t *testing.T,
) {
	db := testutil.OpenSQLite(t)

	repository := newSeededWorkloadRepository(
		t,
		db,
	)

	ctx := context.Background()
	now := testTime()

	err := repository.Release(
		ctx,
		domain.SPIFFEIDOrderClient,
		now,
	)
	if !errors.Is(err, ErrInvalidState) {
		t.Fatalf(
			"Release(active workload) error = %v, want ErrInvalidState",
			err,
		)
	}

	err = repository.Quarantine(
		ctx,
		domain.SPIFFEIDReportClient,
		69,
		now,
	)
	if err == nil ||
		!strings.Contains(
			err.Error(),
			"must be at least 70",
		) {
		t.Fatalf(
			"Quarantine(score 69) error = %v",
			err,
		)
	}

	err = repository.Quarantine(
		ctx,
		domain.SPIFFEIDReportClient,
		70,
		now,
	)
	if err != nil {
		t.Fatalf(
			"Quarantine(score 70) unexpected error: %v",
			err,
		)
	}

	err = repository.ResetRisk(
		ctx,
		domain.SPIFFEIDReportClient,
		now.Add(time.Minute),
	)
	if !errors.Is(err, ErrInvalidState) {
		t.Fatalf(
			"ResetRisk(quarantined workload) error = %v, want ErrInvalidState",
			err,
		)
	}
}

func TestSQLiteWorkloadRepositoryValidation(
	t *testing.T,
) {
	db := testutil.OpenSQLite(t)

	repository := newSeededWorkloadRepository(
		t,
		db,
	)

	ctx := context.Background()
	now := testTime()

	_, err := repository.FindBySPIFFEID(
		ctx,
		"spiffe://containgo.local/ns/containgo/sa/unknown",
	)
	if err == nil ||
		!strings.Contains(
			err.Error(),
			"unknown workload SPIFFE ID",
		) {
		t.Fatalf(
			"FindBySPIFFEID(unknown) error = %v",
			err,
		)
	}

	err = repository.UpdateRisk(
		ctx,
		domain.SPIFFEIDOrderClient,
		-1,
		0,
		now,
	)
	if err == nil ||
		!strings.Contains(
			err.Error(),
			"risk score must not be negative",
		) {
		t.Fatalf(
			"UpdateRisk(negative score) error = %v",
			err,
		)
	}

	err = repository.EnsureKnown(
		nil,
		now,
	)
	if err == nil ||
		!strings.Contains(
			err.Error(),
			"context must not be nil",
		) {
		t.Fatalf(
			"EnsureKnown(nil context) error = %v",
			err,
		)
	}
}

func TestSQLiteWorkloadRepositoryPreservesStateDuringEnsure(
	t *testing.T,
) {
	db := testutil.OpenSQLite(t)

	repository := newSeededWorkloadRepository(
		t,
		db,
	)

	ctx := context.Background()
	now := testTime()

	err := repository.Quarantine(
		ctx,
		domain.SPIFFEIDReportClient,
		95,
		now.Add(time.Minute),
	)
	if err != nil {
		t.Fatalf(
			"Quarantine() unexpected error: %v",
			err,
		)
	}

	err = repository.EnsureKnown(
		ctx,
		now.Add(2*time.Minute),
	)
	if err != nil {
		t.Fatalf(
			"EnsureKnown() unexpected error: %v",
			err,
		)
	}

	workload, err := repository.FindBySPIFFEID(
		ctx,
		domain.SPIFFEIDReportClient,
	)
	if err != nil {
		t.Fatalf(
			"FindBySPIFFEID() unexpected error: %v",
			err,
		)
	}

	if !workload.IsQuarantined() {
		t.Fatal(
			"EnsureKnown() released a quarantined workload",
		)
	}

	if workload.RiskScore != 95 {
		t.Fatalf(
			"score after EnsureKnown() = %d, want 95",
			workload.RiskScore,
		)
	}
}
func newSeededWorkloadRepository(
	t *testing.T,
	db *sql.DB,
) *SQLiteWorkloadRepository {
	t.Helper()

	repository, err := NewSQLiteWorkloadRepository(
		db,
	)
	if err != nil {
		t.Fatalf(
			"NewSQLiteWorkloadRepository() unexpected error: %v",
			err,
		)
	}

	err = repository.EnsureKnown(
		context.Background(),
		testTime(),
	)
	if err != nil {
		t.Fatalf(
			"EnsureKnown() unexpected error: %v",
			err,
		)
	}

	return repository
}

func testTime() time.Time {
	return time.Date(
		2026,
		time.June,
		20,
		12,
		0,
		0,
		0,
		time.UTC,
	)
}
