package application

import (
	"context"
	"time"

	"containgo.local/containgo/internal/domain"
)

// WorkloadRepository contains the workload operations needed by the
// quarantine application service.
type WorkloadRepository interface {
	Quarantine(
		ctx context.Context,
		spiffeID string,
		score int,
		quarantinedAt time.Time,
	) error

	Release(
		ctx context.Context,
		spiffeID string,
		releasedAt time.Time,
	) error
}

// IncidentRepository contains the incident operation needed by the
// quarantine application service.
type IncidentRepository interface {
	Create(
		ctx context.Context,
		spiffeID string,
		score int,
		reasons []domain.RiskContribution,
		quarantinedAt time.Time,
	) (domain.Incident, error)
}

// AuditRepository contains the audit operation needed by application
// services.
type AuditRepository interface {
	Create(
		ctx context.Context,
		record domain.AuditRecord,
	) (domain.AuditRecord, error)
}

// IncidentReleaseRepository contains the incident operations needed by the
// workload-release application service.
type IncidentReleaseRepository interface {
	FindOpenByWorkload(
		ctx context.Context,
		spiffeID string,
	) (domain.Incident, error)

	Release(
		ctx context.Context,
		spiffeID string,
		releasedBy string,
		releasedAt time.Time,
	) (domain.Incident, error)
}
