package controlplane

import (
	"context"
	"time"

	"containgo.local/containgo/internal/application"
	"containgo.local/containgo/internal/domain"
	"containgo.local/containgo/internal/risk"
)

// RiskEngine contains the risk operations required by the control plane.
type RiskEngine interface {
	Evaluate(
		event domain.SecurityEvent,
	) (risk.EvaluationResult, error)

	Restore(
		workloadID string,
		score int,
		quarantined bool,
		observations []risk.Observation,
	) error

	Reset(workloadID string) error
}

// WorkloadRepository manages current workload state.
type WorkloadRepository interface {
	EnsureKnown(
		ctx context.Context,
		now time.Time,
	) error

	FindBySPIFFEID(
		ctx context.Context,
		spiffeID string,
	) (domain.Workload, error)

	List(
		ctx context.Context,
	) ([]domain.Workload, error)

	UpdateRisk(
		ctx context.Context,
		spiffeID string,
		score int,
		deniedRequests int,
		lastSeenAt time.Time,
	) error

	ResetRisk(
		ctx context.Context,
		spiffeID string,
		resetAt time.Time,
	) error
}

// EventRepository stores and queries trusted gateway events.
type EventRepository interface {
	ExistsByRequestID(
		ctx context.Context,
		requestID string,
	) (bool, error)

	Create(
		ctx context.Context,
		event domain.SecurityEvent,
		contributions []domain.RiskContribution,
		createdAt time.Time,
	) (domain.StoredEvent, error)

	ListByWorkload(
		ctx context.Context,
		spiffeID string,
		limit int,
	) ([]domain.StoredEvent, error)
}

// IncidentRepository exposes incident history to the administrative API.
type IncidentRepository interface {
	ListByWorkload(
		ctx context.Context,
		spiffeID string,
		limit int,
	) ([]domain.Incident, error)
}

// AuditRepository stores and queries immutable audit records.
type AuditRepository interface {
	Create(
		ctx context.Context,
		record domain.AuditRecord,
	) (domain.AuditRecord, error)

	ListRecent(
		ctx context.Context,
		limit int,
	) ([]domain.AuditRecord, error)

	ListByTarget(
		ctx context.Context,
		targetSPIFFEID string,
		limit int,
	) ([]domain.AuditRecord, error)
}

// QuarantineWorkflow opens a quarantine incident and updates workload state.
type QuarantineWorkflow interface {
	Quarantine(
		ctx context.Context,
		request application.QuarantineRequest,
	) (application.QuarantineResult, error)
}

// ReleaseWorkflow closes the active incident and reactivates the workload.
type ReleaseWorkflow interface {
	Release(
		ctx context.Context,
		request application.ReleaseRequest,
	) (application.ReleaseResult, error)
}

// QuarantineEnforcer synchronizes runtime deny state with the policy engine.
type QuarantineEnforcer interface {
	Check(ctx context.Context) error

	SetQuarantined(
		ctx context.Context,
		spiffeID string,
		quarantined bool,
	) error

	ReplaceQuarantined(
		ctx context.Context,
		spiffeIDs []string,
	) error
}

// Clock supplies deterministic UTC timestamps to the service.
type Clock interface {
	Now() time.Time
}
