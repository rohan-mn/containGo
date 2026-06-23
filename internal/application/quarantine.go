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

// QuarantineRequest contains the information required to quarantine one
// workload after its accumulated risk reaches the quarantine threshold.
type QuarantineRequest struct {
	WorkloadSPIFFEID string
	ActorSPIFFEID    string
	Score            int
	Reasons          []domain.RiskContribution
	OccurredAt       time.Time
}

// Validate checks the quarantine command before any repository is changed.
func (r QuarantineRequest) Validate() error {
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
			"unknown quarantine actor SPIFFE ID %q",
			r.ActorSPIFFEID,
		)
	}

	if !domain.ReachesQuarantineThreshold(r.Score) {
		return fmt.Errorf(
			"quarantine score must be at least %d",
			domain.QuarantineThreshold,
		)
	}

	if len(r.Reasons) == 0 {
		return errors.New(
			"quarantine request must include at least one reason",
		)
	}

	for index, reason := range r.Reasons {
		if err := reason.Validate(); err != nil {
			return fmt.Errorf(
				"validate quarantine reason %d: %w",
				index,
				err,
			)
		}
	}

	if r.OccurredAt.IsZero() {
		return errors.New(
			"quarantine timestamp must not be zero",
		)
	}

	return nil
}

// QuarantineResult contains the records created by one successful
// quarantine workflow.
type QuarantineResult struct {
	Incident     domain.Incident
	AuditRecords []domain.AuditRecord
}

// QuarantineService coordinates workload, incident, and audit persistence.
type QuarantineService struct {
	workloads WorkloadRepository
	incidents IncidentRepository
	audits    AuditRepository
}

// NewQuarantineService creates the quarantine workflow service.
func NewQuarantineService(
	workloads WorkloadRepository,
	incidents IncidentRepository,
	audits AuditRepository,
) (*QuarantineService, error) {
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

	return &QuarantineService{
		workloads: workloads,
		incidents: incidents,
		audits:    audits,
	}, nil
}

// Quarantine executes the complete workload-quarantine workflow.
func (s *QuarantineService) Quarantine(
	ctx context.Context,
	request QuarantineRequest,
) (QuarantineResult, error) {
	if ctx == nil {
		return QuarantineResult{}, errors.New(
			"context must not be nil",
		)
	}

	if err := ctx.Err(); err != nil {
		return QuarantineResult{}, fmt.Errorf(
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
	request.Reasons = append(
		[]domain.RiskContribution(nil),
		request.Reasons...,
	)

	if err := request.Validate(); err != nil {
		return QuarantineResult{}, fmt.Errorf(
			"validate quarantine request: %w",
			err,
		)
	}

	if err := s.workloads.Quarantine(
		ctx,
		request.WorkloadSPIFFEID,
		request.Score,
		request.OccurredAt,
	); err != nil {
		return QuarantineResult{}, fmt.Errorf(
			"quarantine workload %q: %w",
			request.WorkloadSPIFFEID,
			err,
		)
	}

	incident, err := s.incidents.Create(
		ctx,
		request.WorkloadSPIFFEID,
		request.Score,
		request.Reasons,
		request.OccurredAt,
	)
	if err != nil {
		rollbackErr := s.workloads.Release(
			ctx,
			request.WorkloadSPIFFEID,
			request.OccurredAt,
		)
		if rollbackErr != nil {
			return QuarantineResult{}, fmt.Errorf(
				"create quarantine incident: %w; rollback workload release failed: %v",
				err,
				rollbackErr,
			)
		}

		return QuarantineResult{}, fmt.Errorf(
			"create quarantine incident: %w",
			err,
		)
	}

	result := QuarantineResult{
		Incident: incident,
		AuditRecords: make(
			[]domain.AuditRecord,
			0,
			2,
		),
	}

	workloadAudit, err := s.createAuditRecord(
		ctx,
		request,
		domain.AuditActionWorkloadQuarantined,
		map[string]any{
			"incident_id": incident.ID,
			"score":       request.Score,
			"status":      string(domain.WorkloadStatusQuarantined),
		},
	)
	if err != nil {
		return result, fmt.Errorf(
			"create workload-quarantined audit record: %w",
			err,
		)
	}

	result.AuditRecords = append(
		result.AuditRecords,
		workloadAudit,
	)

	incidentAudit, err := s.createAuditRecord(
		ctx,
		request,
		domain.AuditActionIncidentCreated,
		map[string]any{
			"incident_id": incident.ID,
			"score":       request.Score,
			"reason_count": len(
				request.Reasons,
			),
		},
	)
	if err != nil {
		return result, fmt.Errorf(
			"create incident-created audit record: %w",
			err,
		)
	}

	result.AuditRecords = append(
		result.AuditRecords,
		incidentAudit,
	)

	return result, nil
}

func (s *QuarantineService) createAuditRecord(
	ctx context.Context,
	request QuarantineRequest,
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
