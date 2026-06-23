package domain

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestAuditRecordValidateSupportedActions(
	t *testing.T,
) {
	actions := []AuditAction{
		AuditActionIncidentCreated,
		AuditActionWorkloadQuarantined,
		AuditActionOPAQuarantineAdded,
		AuditActionIncidentReleased,
		AuditActionWorkloadReleased,
		AuditActionOPAQuarantineRemoved,
		AuditActionRiskReset,
	}

	for _, action := range actions {
		t.Run(
			string(action),
			func(t *testing.T) {
				record := validAuditRecord()
				record.Action = action

				if err := record.Validate(); err != nil {
					t.Fatalf(
						"Validate() error: %v",
						err,
					)
				}
			},
		)
	}
}

func TestAuditRecordValidateRejectsInvalidData(
	t *testing.T,
) {
	tests := []struct {
		name          string
		modify        func(*AuditRecord)
		errorContains string
	}{
		{
			name: "negative ID",
			modify: func(record *AuditRecord) {
				record.ID = -1
			},
			errorContains: "must not be negative",
		},
		{
			name: "unknown actor",
			modify: func(record *AuditRecord) {
				record.ActorSPIFFEID =
					"spiffe://containgo.local/unknown"
			},
			errorContains: "unknown audit actor",
		},
		{
			name: "unsupported action",
			modify: func(record *AuditRecord) {
				record.Action =
					AuditAction("unsupported")
			},
			errorContains: "unsupported audit action",
		},
		{
			name: "unknown target",
			modify: func(record *AuditRecord) {
				record.TargetSPIFFEID =
					"spiffe://containgo.local/unknown"
			},
			errorContains: "unknown audit target",
		},
		{
			name: "empty details",
			modify: func(record *AuditRecord) {
				record.DetailsJSON = nil
			},
			errorContains: "must not be empty",
		},
		{
			name: "invalid details JSON",
			modify: func(record *AuditRecord) {
				record.DetailsJSON =
					json.RawMessage(`{"incident_id":`)
			},
			errorContains: "parse audit details JSON",
		},
		{
			name: "details JSON array",
			modify: func(record *AuditRecord) {
				record.DetailsJSON =
					json.RawMessage(`[1, 2, 3]`)
			},
			errorContains: "parse audit details JSON",
		},
		{
			name: "details JSON null",
			modify: func(record *AuditRecord) {
				record.DetailsJSON =
					json.RawMessage(`null`)
			},
			errorContains: "must be an object",
		},
		{
			name: "zero occurred-at timestamp",
			modify: func(record *AuditRecord) {
				record.OccurredAt = time.Time{}
			},
			errorContains: "must not be zero",
		},
	}

	for _, test := range tests {
		t.Run(
			test.name,
			func(t *testing.T) {
				record := validAuditRecord()
				test.modify(&record)

				err := record.Validate()
				if err == nil {
					t.Fatal(
						"Validate() returned nil error",
					)
				}

				if !strings.Contains(
					err.Error(),
					test.errorContains,
				) {
					t.Fatalf(
						"Validate() error = %q, want text %q",
						err,
						test.errorContains,
					)
				}
			},
		)
	}
}

func TestAuditRecordValidateAllowsEmptyTarget(
	t *testing.T,
) {
	record := validAuditRecord()
	record.TargetSPIFFEID = ""

	if err := record.Validate(); err != nil {
		t.Fatalf(
			"Validate() error: %v",
			err,
		)
	}
}

func validAuditRecord() AuditRecord {
	return AuditRecord{
		ID:             0,
		ActorSPIFFEID:  SPIFFEIDDemoctl,
		Action:         AuditActionIncidentCreated,
		TargetSPIFFEID: SPIFFEIDReportClient,
		DetailsJSON:    json.RawMessage(`{"incident_id":4,"score":120}`),
		OccurredAt:     time.Date(2026, time.June, 20, 8, 30, 0, 0, time.UTC),
	}
}
