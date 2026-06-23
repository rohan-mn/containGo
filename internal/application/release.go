package application

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"containgo.local/containgo/internal/domain"
)

// ReleaseRequest contains the information required to release a quarantined
// workload.
type ReleaseRequest struct {
	WorkloadSPIFFEID string
	ActorSPIFFEID    string
	OccurredAt       time.Time
}

// Validate checks the release request before repositories are changed.
func (r ReleaseRequest) Validate() error {
	if !domain.IsKnownWorkloadID(
		strings.TrimSpace(r.WorkloadSPIFFEID),
	) {
		return fmt.Errorf(
			"unknown workload SPIFFE ID %q",
			r.WorkloadSPIFFEID,
		)
	}

	if !domain.IsKnownWorkloadID(
		strings.TrimSpace(r.ActorSPIFFEID),
	) {
		return fmt.Errorf(
			"unknown release actor SPIFFE ID %q",
			r.ActorSPIFFEID,
		)
	}

	if r.OccurredAt.IsZero() {
		return errors.New(
			"release timestamp must not be zero",
		)
	}

	return nil
}

// ReleaseResult contains the records produced by a successful release.
type ReleaseResult struct {
	Incident     domain.Incident
	AuditRecords []domain.AuditRecord
}

// ReleaseService coordinates workload, incident, and audit persistence during
// an administrator-approved release.
type ReleaseService struct {
	workloads WorkloadRepository
	incidents IncidentReleaseRepository
	audits    AuditRepository
}

// NewReleaseService creates the workload-release service.
func NewReleaseService(
	workloads WorkloadRepository,
	incidents IncidentReleaseRepository,
	audits AuditRepository,
) (*ReleaseService, error) {
	if workloads == nil {
		return nil, errors.New(
			"workload repository must not be nil",
		)
	}

	if incidents == nil {
		return nil, errors.New(
			"incident repository must not be nil",
		)
	}

	if audits == nil {
		return nil, errors.New(
			"audit repository must not be nil",
		)
	}

	return &ReleaseService{
		workloads: workloads,
		incidents: incidents,
		audits:    audits,
	}, nil
}

// Release executes the complete workload-release workflow.
func (s *ReleaseService) Release(
	ctx context.Context,
	request ReleaseRequest,
) (ReleaseResult, error) {
	if ctx == nil {
		return ReleaseResult{}, errors.New(
			"context must not be nil",
		)
	}

	if err := ctx.Err(); err != nil {
		return ReleaseResult{}, fmt.Errorf(
			"context is not usable: %w",
			err,
		)
	}

	request.WorkloadSPIFFEID = strings.TrimSpace(
		request.WorkloadSPIFFEID,
	)
	request.ActorSPIFFEID = strings.TrimSpace(
		request.ActorSPIFFEID,
	)
	request.OccurredAt = request.OccurredAt.UTC()

	if err := request.Validate(); err != nil {
		return ReleaseResult{}, fmt.Errorf(
			"validate release request: %w",
			err,
		)
	}

	openIncident, err := s.incidents.FindOpenByWorkload(
		ctx,
		request.WorkloadSPIFFEID,
	)
	if err != nil {
		return ReleaseResult{}, fmt.Errorf(
			"find open incident for workload %q: %w",
			request.WorkloadSPIFFEID,
			err,
		)
	}

	if !openIncident.IsOpen() {
		return ReleaseResult{}, errors.New(
			"incident repository returned a non-open incident",
		)
	}

	if err = s.workloads.Release(
		ctx,
		request.WorkloadSPIFFEID,
		request.OccurredAt,
	); err != nil {
		return ReleaseResult{}, fmt.Errorf(
			"release workload %q: %w",
			request.WorkloadSPIFFEID,
			err,
		)
	}

	releasedIncident, err := s.incidents.Release(
		ctx,
		request.WorkloadSPIFFEID,
		request.ActorSPIFFEID,
		request.OccurredAt,
	)
	if err != nil {
		compensationErr := s.workloads.Quarantine(
			ctx,
			request.WorkloadSPIFFEID,
			openIncident.ScoreAtQuarantine,
			request.OccurredAt,
		)

		if compensationErr != nil {
			return ReleaseResult{}, errors.Join(
				fmt.Errorf(
					"release incident: %w",
					err,
				),
				fmt.Errorf(
					"restore workload quarantine: %w",
					compensationErr,
				),
			)
		}

		return ReleaseResult{}, fmt.Errorf(
			"release incident: %w",
			err,
		)
	}

	result := ReleaseResult{
		Incident: releasedIncident,
		AuditRecords: make(
			[]domain.AuditRecord,
			0,
			2,
		),
	}

	incidentAudit, err := s.createAuditRecord(
		ctx,
		request,
		domain.AuditActionIncidentReleased,
		map[string]any{
			"incident_id":         releasedIncident.ID,
			"score_at_quarantine": releasedIncident.ScoreAtQuarantine,
			"released_by":         request.ActorSPIFFEID,
		},
	)
	if err != nil {
		return result, fmt.Errorf(
			"create incident-released audit record: %w",
			err,
		)
	}

	result.AuditRecords = append(
		result.AuditRecords,
		incidentAudit,
	)

	workloadAudit, err := s.createAuditRecord(
		ctx,
		request,
		domain.AuditActionWorkloadReleased,
		map[string]any{
			"incident_id": releasedIncident.ID,
			"status":      string(domain.WorkloadStatusActive),
		},
	)
	if err != nil {
		return result, fmt.Errorf(
			"create workload-released audit record: %w",
			err,
		)
	}

	result.AuditRecords = append(
		result.AuditRecords,
		workloadAudit,
	)

	return result, nil
}

func (s *ReleaseService) createAuditRecord(
	ctx context.Context,
	request ReleaseRequest,
	action domain.AuditAction,
	details map[string]any,
) (domain.AuditRecord, error) {
	detailsJSON, err := json.Marshal(details)
	if err != nil {
		return domain.AuditRecord{}, fmt.Errorf(
			"encode audit details: %w",
			err,
		)
	}

	record := domain.AuditRecord{
		ActorSPIFFEID:  request.ActorSPIFFEID,
		Action:         action,
		TargetSPIFFEID: request.WorkloadSPIFFEID,
		DetailsJSON:    detailsJSON,
		OccurredAt:     request.OccurredAt,
	}

	storedRecord, err := s.audits.Create(
		ctx,
		record,
	)
	if err != nil {
		return domain.AuditRecord{}, err
	}

	return storedRecord, nil
}
