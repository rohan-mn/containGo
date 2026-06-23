package repository

import (
	"context"
	"time"

	"containgo.local/containgo/internal/domain"
)

// IncidentRepository manages quarantine incident lifecycles.
type IncidentRepository interface {
	Create(
		ctx context.Context,
		spiffeID string,
		score int,
		reasons []domain.RiskContribution,
		quarantinedAt time.Time,
	) (domain.Incident, error)

	FindOpenByWorkload(
		ctx context.Context,
		spiffeID string,
	) (domain.Incident, error)

	ListByWorkload(
		ctx context.Context,
		spiffeID string,
		limit int,
	) ([]domain.Incident, error)

	Release(
		ctx context.Context,
		spiffeID string,
		releasedBy string,
		releasedAt time.Time,
	) (domain.Incident, error)
}

// AuditRepository stores and queries immutable security audit records.
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

// Compile-time checks ensure the SQLite repositories implement the
// repository interfaces.
var (
	_ IncidentRepository = (*SQLiteIncidentRepository)(nil)
	_ AuditRepository    = (*SQLiteAuditRepository)(nil)
)
