package domain

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// AuditAction identifies a security-sensitive system or administrator action.
type AuditAction string

const (
	AuditActionIncidentCreated AuditAction = "incident_created"

	AuditActionWorkloadQuarantined AuditAction = "workload_quarantined"

	AuditActionOPAQuarantineAdded AuditAction = "opa_quarantine_added"

	AuditActionIncidentReleased AuditAction = "incident_released"

	AuditActionWorkloadReleased AuditAction = "workload_released"

	AuditActionOPAQuarantineRemoved AuditAction = "opa_quarantine_removed"

	AuditActionRiskReset AuditAction = "risk_reset"
)

// AuditRecord represents an immutable security audit entry.
type AuditRecord struct {
	ID             int64           `json:"id"`
	ActorSPIFFEID  string          `json:"actor_spiffe_id"`
	Action         AuditAction     `json:"action"`
	TargetSPIFFEID string          `json:"target_spiffe_id,omitempty"`
	DetailsJSON    json.RawMessage `json:"details_json"`
	OccurredAt     time.Time       `json:"occurred_at"`
}

// Validate checks an audit record before persistence or display.
func (a AuditRecord) Validate() error {
	if a.ID < 0 {
		return errors.New(
			"audit record ID must not be negative",
		)
	}

	if !IsKnownWorkloadID(a.ActorSPIFFEID) {
		return fmt.Errorf(
			"unknown audit actor SPIFFE ID %q",
			a.ActorSPIFFEID,
		)
	}

	if !isSupportedAuditAction(a.Action) {
		return fmt.Errorf(
			"unsupported audit action %q",
			a.Action,
		)
	}

	if strings.TrimSpace(a.TargetSPIFFEID) != "" &&
		!IsKnownWorkloadID(a.TargetSPIFFEID) {
		return fmt.Errorf(
			"unknown audit target SPIFFE ID %q",
			a.TargetSPIFFEID,
		)
	}

	if len(a.DetailsJSON) == 0 {
		return errors.New(
			"audit details JSON must not be empty",
		)
	}

	var details map[string]any

	if err := json.Unmarshal(
		a.DetailsJSON,
		&details,
	); err != nil {
		return fmt.Errorf(
			"parse audit details JSON: %w",
			err,
		)
	}

	if details == nil {
		return errors.New(
			"audit details JSON must be an object",
		)
	}

	if a.OccurredAt.IsZero() {
		return errors.New(
			"audit occurred-at timestamp must not be zero",
		)
	}

	return nil
}

func isSupportedAuditAction(
	action AuditAction,
) bool {
	switch action {
	case AuditActionIncidentCreated,
		AuditActionWorkloadQuarantined,
		AuditActionOPAQuarantineAdded,
		AuditActionIncidentReleased,
		AuditActionWorkloadReleased,
		AuditActionOPAQuarantineRemoved,
		AuditActionRiskReset:
		return true

	default:
		return false
	}
}
