package repository

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"containgo.local/containgo/internal/domain"
	"containgo.local/containgo/internal/testutil"
)

func TestSQLiteAuditRepositoryCreateAndQuery(
	t *testing.T,
) {
	db := testutil.OpenSQLite(t)
	seedWorkloads(t, db)

	repository, err := NewSQLiteAuditRepository(db)
	if err != nil {
		t.Fatalf(
			"NewSQLiteAuditRepository() error: %v",
			err,
		)
	}

	ctx := context.Background()
	start := repositoryTestTime()

	first, err := repository.Create(
		ctx,
		domain.AuditRecord{
			ActorSPIFFEID:  domain.SPIFFEIDDemoctl,
			Action:         domain.AuditActionIncidentCreated,
			TargetSPIFFEID: domain.SPIFFEIDReportClient,
			DetailsJSON: mustAuditDetails(
				t,
				map[string]any{
					"incident_id": 1,
					"score":       120,
				},
			),
			OccurredAt: start,
		},
	)
	if err != nil {
		t.Fatalf(
			"first Create() error: %v",
			err,
		)
	}

	second, err := repository.Create(
		ctx,
		domain.AuditRecord{
			ActorSPIFFEID:  domain.SPIFFEIDDemoctl,
			Action:         domain.AuditActionWorkloadQuarantined,
			TargetSPIFFEID: domain.SPIFFEIDReportClient,
			DetailsJSON: mustAuditDetails(
				t,
				map[string]any{
					"incident_id": 1,
					"status":      "quarantined",
				},
			),
			OccurredAt: start.Add(time.Second),
		},
	)
	if err != nil {
		t.Fatalf(
			"second Create() error: %v",
			err,
		)
	}

	third, err := repository.Create(
		ctx,
		domain.AuditRecord{
			ActorSPIFFEID:  domain.SPIFFEIDDemoctl,
			Action:         domain.AuditActionRiskReset,
			TargetSPIFFEID: domain.SPIFFEIDOrderClient,
			DetailsJSON: mustAuditDetails(
				t,
				map[string]any{
					"previous_score": 80,
					"new_score":      0,
				},
			),
			OccurredAt: start.Add(
				2 * time.Second,
			),
		},
	)
	if err != nil {
		t.Fatalf(
			"third Create() error: %v",
			err,
		)
	}

	if first.ID <= 0 ||
		second.ID <= 0 ||
		third.ID <= 0 {
		t.Fatalf(
			"audit IDs must be positive: %d, %d, %d",
			first.ID,
			second.ID,
			third.ID,
		)
	}

	recent, err := repository.ListRecent(
		ctx,
		10,
	)
	if err != nil {
		t.Fatalf(
			"ListRecent() error: %v",
			err,
		)
	}

	if len(recent) != 3 {
		t.Fatalf(
			"recent record count = %d, want 3",
			len(recent),
		)
	}

	if recent[0].ID != third.ID {
		t.Fatalf(
			"newest record ID = %d, want %d",
			recent[0].ID,
			third.ID,
		)
	}

	if recent[1].ID != second.ID {
		t.Fatalf(
			"second record ID = %d, want %d",
			recent[1].ID,
			second.ID,
		)
	}

	if recent[2].ID != first.ID {
		t.Fatalf(
			"oldest record ID = %d, want %d",
			recent[2].ID,
			first.ID,
		)
	}

	targetRecords, err :=
		repository.ListByTarget(
			ctx,
			domain.SPIFFEIDReportClient,
			10,
		)
	if err != nil {
		t.Fatalf(
			"ListByTarget() error: %v",
			err,
		)
	}

	if len(targetRecords) != 2 {
		t.Fatalf(
			"target record count = %d, want 2",
			len(targetRecords),
		)
	}

	if targetRecords[0].ID != second.ID {
		t.Fatalf(
			"newest target record ID = %d, want %d",
			targetRecords[0].ID,
			second.ID,
		)
	}

	if targetRecords[1].ID != first.ID {
		t.Fatalf(
			"oldest target record ID = %d, want %d",
			targetRecords[1].ID,
			first.ID,
		)
	}
}

func TestSQLiteAuditRepositorySupportsNoTarget(
	t *testing.T,
) {
	db := testutil.OpenSQLite(t)
	seedWorkloads(t, db)

	repository, err := NewSQLiteAuditRepository(db)
	if err != nil {
		t.Fatalf(
			"NewSQLiteAuditRepository() error: %v",
			err,
		)
	}

	record, err := repository.Create(
		context.Background(),
		domain.AuditRecord{
			ActorSPIFFEID: domain.SPIFFEIDDemoctl,
			Action:        domain.AuditActionRiskReset,
			DetailsJSON: mustAuditDetails(
				t,
				map[string]any{
					"scope": "all_workloads",
				},
			),
			OccurredAt: repositoryTestTime(),
		},
	)
	if err != nil {
		t.Fatalf(
			"Create() error: %v",
			err,
		)
	}

	if record.TargetSPIFFEID != "" {
		t.Fatalf(
			"target SPIFFE ID = %q, want empty",
			record.TargetSPIFFEID,
		)
	}

	records, err := repository.ListRecent(
		context.Background(),
		10,
	)
	if err != nil {
		t.Fatalf(
			"ListRecent() error: %v",
			err,
		)
	}

	if len(records) != 1 {
		t.Fatalf(
			"record count = %d, want 1",
			len(records),
		)
	}

	if records[0].TargetSPIFFEID != "" {
		t.Fatalf(
			"stored target SPIFFE ID = %q, want empty",
			records[0].TargetSPIFFEID,
		)
	}
}

func TestSQLiteAuditRepositoryRejectsInvalidCreate(
	t *testing.T,
) {
	db := testutil.OpenSQLite(t)
	seedWorkloads(t, db)

	repository, err := NewSQLiteAuditRepository(db)
	if err != nil {
		t.Fatalf(
			"NewSQLiteAuditRepository() error: %v",
			err,
		)
	}

	ctx := context.Background()
	now := repositoryTestTime()

	validRecord := domain.AuditRecord{
		ActorSPIFFEID:  domain.SPIFFEIDDemoctl,
		Action:         domain.AuditActionIncidentCreated,
		TargetSPIFFEID: domain.SPIFFEIDReportClient,
		DetailsJSON: mustAuditDetails(
			t,
			map[string]any{
				"incident_id": 5,
			},
		),
		OccurredAt: now,
	}

	recordWithID := validRecord
	recordWithID.ID = 42

	_, err = repository.Create(
		ctx,
		recordWithID,
	)
	if err == nil ||
		!strings.Contains(
			err.Error(),
			"ID must be zero",
		) {
		t.Fatalf(
			"Create(record with ID) error = %v",
			err,
		)
	}

	invalidJSON := validRecord
	invalidJSON.DetailsJSON = json.RawMessage(
		`{"incident_id":`,
	)

	_, err = repository.Create(
		ctx,
		invalidJSON,
	)
	if err == nil {
		t.Fatal(
			"Create(invalid JSON) returned nil error",
		)
	}

	unknownActor := validRecord
	unknownActor.ActorSPIFFEID =
		"spiffe://containgo.local/unknown"

	_, err = repository.Create(
		ctx,
		unknownActor,
	)
	if err == nil ||
		!strings.Contains(
			err.Error(),
			"unknown audit actor",
		) {
		t.Fatalf(
			"Create(unknown actor) error = %v",
			err,
		)
	}

	unknownTarget := validRecord
	unknownTarget.TargetSPIFFEID =
		"spiffe://containgo.local/unknown"

	_, err = repository.Create(
		ctx,
		unknownTarget,
	)
	if err == nil ||
		!strings.Contains(
			err.Error(),
			"unknown audit target",
		) {
		t.Fatalf(
			"Create(unknown target) error = %v",
			err,
		)
	}
}

func TestSQLiteAuditRepositoryRequiresRegisteredActor(
	t *testing.T,
) {
	db := testutil.OpenSQLite(t)

	repository, err := NewSQLiteAuditRepository(db)
	if err != nil {
		t.Fatalf(
			"NewSQLiteAuditRepository() error: %v",
			err,
		)
	}

	_, err = repository.Create(
		context.Background(),
		domain.AuditRecord{
			ActorSPIFFEID:  domain.SPIFFEIDDemoctl,
			Action:         domain.AuditActionIncidentCreated,
			TargetSPIFFEID: "",
			DetailsJSON: mustAuditDetails(
				t,
				map[string]any{
					"incident_id": 1,
				},
			),
			OccurredAt: repositoryTestTime(),
		},
	)

	if !errors.Is(err, ErrNotFound) {
		t.Fatalf(
			"Create(unregistered actor) error = %v, want ErrNotFound",
			err,
		)
	}
}

func TestSQLiteAuditRepositoryQueryValidation(
	t *testing.T,
) {
	db := testutil.OpenSQLite(t)
	seedWorkloads(t, db)

	repository, err := NewSQLiteAuditRepository(db)
	if err != nil {
		t.Fatalf(
			"NewSQLiteAuditRepository() error: %v",
			err,
		)
	}

	ctx := context.Background()

	_, err = repository.ListRecent(
		ctx,
		0,
	)
	if err == nil ||
		!strings.Contains(
			err.Error(),
			"between 1 and 200",
		) {
		t.Fatalf(
			"ListRecent(limit 0) error = %v",
			err,
		)
	}

	_, err = repository.ListRecent(
		ctx,
		201,
	)
	if err == nil ||
		!strings.Contains(
			err.Error(),
			"between 1 and 200",
		) {
		t.Fatalf(
			"ListRecent(limit 201) error = %v",
			err,
		)
	}

	_, err = repository.ListByTarget(
		ctx,
		"spiffe://containgo.local/unknown",
		10,
	)
	if err == nil {
		t.Fatal(
			"ListByTarget(unknown target) returned nil error",
		)
	}

	cancelledContext, cancel :=
		context.WithCancel(
			context.Background(),
		)
	cancel()

	_, err = repository.ListRecent(
		cancelledContext,
		10,
	)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf(
			"ListRecent(cancelled context) error = %v, want context.Canceled",
			err,
		)
	}
}

func TestNewSQLiteAuditRepositoryRejectsNilDatabase(
	t *testing.T,
) {
	_, err := NewSQLiteAuditRepository(nil)

	if err == nil {
		t.Fatal(
			"NewSQLiteAuditRepository(nil) returned nil error",
		)
	}
}

func mustAuditDetails(
	t *testing.T,
	value map[string]any,
) json.RawMessage {
	t.Helper()

	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatalf(
			"json.Marshal() error: %v",
			err,
		)
	}

	return json.RawMessage(encoded)
}
