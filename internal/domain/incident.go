package domain

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

// IncidentStatus represents the lifecycle state of a quarantine incident.
type IncidentStatus string

const (
	IncidentStatusOpen     IncidentStatus = "open"
	IncidentStatusReleased IncidentStatus = "released"
)

// IncidentReason records one risk contribution associated with an incident.
type IncidentReason struct {
	ID                 int64     `json:"id"`
	IncidentID         int64     `json:"incident_id"`
	RiskContributionID *int64    `json:"risk_contribution_id,omitempty"`
	Rule               RiskRule  `json:"rule"`
	Points             int       `json:"points"`
	Reason             string    `json:"reason"`
	CreatedAt          time.Time `json:"created_at"`
}

// Validate checks a stored incident reason.
func (r IncidentReason) Validate() error {
	if r.ID <= 0 {
		return errors.New(
			"incident reason ID must be greater than zero",
		)
	}

	if r.IncidentID <= 0 {
		return errors.New(
			"incident ID must be greater than zero",
		)
	}

	if r.RiskContributionID != nil &&
		*r.RiskContributionID <= 0 {
		return errors.New(
			"risk contribution ID must be greater than zero",
		)
	}

	contribution := RiskContribution{
		Rule:   r.Rule,
		Points: r.Points,
		Reason: r.Reason,
	}

	if err := contribution.Validate(); err != nil {
		return fmt.Errorf(
			"validate incident contribution: %w",
			err,
		)
	}

	if r.CreatedAt.IsZero() {
		return errors.New(
			"incident reason created-at timestamp must not be zero",
		)
	}

	return nil
}

// Incident represents one quarantine lifecycle for a workload.
type Incident struct {
	ID                int64            `json:"id"`
	WorkloadID        string           `json:"workload_id"`
	Status            IncidentStatus   `json:"status"`
	ScoreAtQuarantine int              `json:"score_at_quarantine"`
	QuarantinedAt     time.Time        `json:"quarantined_at"`
	ReleasedAt        *time.Time       `json:"released_at,omitempty"`
	ReleasedBy        string           `json:"released_by,omitempty"`
	CreatedAt         time.Time        `json:"created_at"`
	UpdatedAt         time.Time        `json:"updated_at"`
	Reasons           []IncidentReason `json:"reasons"`
}

// Validate checks whether an incident contains valid and consistent data.
func (i Incident) Validate() error {
	if i.ID <= 0 {
		return errors.New(
			"incident ID must be greater than zero",
		)
	}

	if !IsKnownWorkloadID(i.WorkloadID) {
		return fmt.Errorf(
			"unknown workload SPIFFE ID %q",
			i.WorkloadID,
		)
	}

	if !ReachesQuarantineThreshold(
		i.ScoreAtQuarantine,
	) {
		return fmt.Errorf(
			"incident score must be at least %d",
			QuarantineThreshold,
		)
	}

	if i.QuarantinedAt.IsZero() {
		return errors.New(
			"quarantine timestamp must not be zero",
		)
	}

	if i.CreatedAt.IsZero() {
		return errors.New(
			"incident created-at timestamp must not be zero",
		)
	}

	if i.UpdatedAt.IsZero() {
		return errors.New(
			"incident updated-at timestamp must not be zero",
		)
	}

	switch i.Status {
	case IncidentStatusOpen:
		if i.ReleasedAt != nil {
			return errors.New(
				"open incident must not have a release timestamp",
			)
		}

		if strings.TrimSpace(i.ReleasedBy) != "" {
			return errors.New(
				"open incident must not have a release actor",
			)
		}

	case IncidentStatusReleased:
		if i.ReleasedAt == nil ||
			i.ReleasedAt.IsZero() {
			return errors.New(
				"released incident must have a release timestamp",
			)
		}

		if !IsKnownWorkloadID(i.ReleasedBy) {
			return fmt.Errorf(
				"unknown release actor SPIFFE ID %q",
				i.ReleasedBy,
			)
		}

	default:
		return fmt.Errorf(
			"unsupported incident status %q",
			i.Status,
		)
	}

	if len(i.Reasons) == 0 {
		return errors.New(
			"incident must include at least one reason",
		)
	}

	for index, reason := range i.Reasons {
		if reason.IncidentID != i.ID {
			return fmt.Errorf(
				"incident reason %d belongs to incident %d, want %d",
				index,
				reason.IncidentID,
				i.ID,
			)
		}

		if err := reason.Validate(); err != nil {
			return fmt.Errorf(
				"validate incident reason %d: %w",
				index,
				err,
			)
		}
	}

	return nil
}

// IsOpen reports whether the workload remains quarantined for this incident.
func (i Incident) IsOpen() bool {
	return i.Status == IncidentStatusOpen
}

// TotalReasonPoints returns the sum of stored incident-reason points.
func (i Incident) TotalReasonPoints() int {
	total := 0

	for _, reason := range i.Reasons {
		total += reason.Points
	}

	return total
}
