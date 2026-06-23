package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"containgo.local/containgo/internal/domain"
)

// SQLiteWorkloadRepository stores workload state in SQLite.
type SQLiteWorkloadRepository struct {
	db *sql.DB
}

// NewSQLiteWorkloadRepository creates a workload repository.
func NewSQLiteWorkloadRepository(
	db *sql.DB,
) (*SQLiteWorkloadRepository, error) {
	if db == nil {
		return nil, errors.New(
			"database must not be nil",
		)
	}

	return &SQLiteWorkloadRepository{
		db: db,
	}, nil
}

// EnsureKnown inserts every registered ContainGo identity.
//
// Existing risk scores, statuses and quarantine timestamps are preserved.
func (r *SQLiteWorkloadRepository) EnsureKnown(
	ctx context.Context,
	now time.Time,
) error {
	if ctx == nil {
		return errors.New(
			"context must not be nil",
		)
	}

	if now.IsZero() {
		return errors.New(
			"timestamp must not be zero",
		)
	}

	now = now.UTC()

	transaction, err := r.db.BeginTx(
		ctx,
		nil,
	)
	if err != nil {
		return fmt.Errorf(
			"begin known-workload transaction: %w",
			err,
		)
	}

	committed := false

	defer func() {
		if !committed {
			_ = transaction.Rollback()
		}
	}()

	for _, spiffeID := range domain.KnownWorkloadIDs() {
		name, found := domain.KnownWorkloadName(
			spiffeID,
		)
		if !found {
			return fmt.Errorf(
				"resolve known workload name for %q",
				spiffeID,
			)
		}

		_, err = transaction.ExecContext(
			ctx,
			`
				INSERT INTO workloads(
					name,
					spiffe_id,
					status,
					risk_score,
					denied_requests,
					created_at,
					updated_at
				)
				VALUES (
					?,
					?,
					'active',
					0,
					0,
					?,
					?
				)
				ON CONFLICT(spiffe_id) DO UPDATE SET
					name = excluded.name,
					updated_at = excluded.updated_at
			`,
			name,
			spiffeID,
			now,
			now,
		)
		if err != nil {
			return fmt.Errorf(
				"ensure known workload %q: %w",
				spiffeID,
				err,
			)
		}
	}

	if err = transaction.Commit(); err != nil {
		return fmt.Errorf(
			"commit known-workload transaction: %w",
			err,
		)
	}

	committed = true

	return nil
}

// FindBySPIFFEID finds one registered workload.
func (r *SQLiteWorkloadRepository) FindBySPIFFEID(
	ctx context.Context,
	spiffeID string,
) (domain.Workload, error) {
	if err := validateContextAndWorkloadID(
		ctx,
		spiffeID,
	); err != nil {
		return domain.Workload{}, err
	}

	row := r.db.QueryRowContext(
		ctx,
		`
			SELECT
				id,
				name,
				spiffe_id,
				status,
				risk_score,
				denied_requests,
				last_seen_at,
				quarantined_at,
				created_at,
				updated_at
			FROM workloads
			WHERE spiffe_id = ?
		`,
		strings.TrimSpace(spiffeID),
	)

	workload, err := scanWorkload(row)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.Workload{}, fmt.Errorf(
			"%w: workload %q",
			ErrNotFound,
			spiffeID,
		)
	}

	if err != nil {
		return domain.Workload{}, fmt.Errorf(
			"find workload %q: %w",
			spiffeID,
			err,
		)
	}

	return workload, nil
}

// List returns all workloads ordered by application name.
func (r *SQLiteWorkloadRepository) List(
	ctx context.Context,
) ([]domain.Workload, error) {
	if ctx == nil {
		return nil, errors.New(
			"context must not be nil",
		)
	}

	rows, err := r.db.QueryContext(
		ctx,
		`
			SELECT
				id,
				name,
				spiffe_id,
				status,
				risk_score,
				denied_requests,
				last_seen_at,
				quarantined_at,
				created_at,
				updated_at
			FROM workloads
			ORDER BY name
		`,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"list workloads: %w",
			err,
		)
	}

	defer func() {
		_ = rows.Close()
	}()

	workloads := make(
		[]domain.Workload,
		0,
	)

	for rows.Next() {
		workload, scanErr := scanWorkload(rows)
		if scanErr != nil {
			return nil, fmt.Errorf(
				"scan workload: %w",
				scanErr,
			)
		}

		workloads = append(
			workloads,
			workload,
		)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf(
			"iterate workloads: %w",
			err,
		)
	}

	return workloads, nil
}

// UpdateRisk updates mutable risk counters for one workload.
func (r *SQLiteWorkloadRepository) UpdateRisk(
	ctx context.Context,
	spiffeID string,
	score int,
	deniedRequests int,
	lastSeenAt time.Time,
) error {
	if err := validateContextAndWorkloadID(
		ctx,
		spiffeID,
	); err != nil {
		return err
	}

	if score < 0 {
		return errors.New(
			"risk score must not be negative",
		)
	}

	if deniedRequests < 0 {
		return errors.New(
			"denied-request count must not be negative",
		)
	}

	if lastSeenAt.IsZero() {
		return errors.New(
			"last-seen timestamp must not be zero",
		)
	}

	lastSeenAt = lastSeenAt.UTC()

	result, err := r.db.ExecContext(
		ctx,
		`
			UPDATE workloads
			SET
				risk_score = ?,
				denied_requests = ?,
				last_seen_at = ?,
				updated_at = ?
			WHERE spiffe_id = ?
		`,
		score,
		deniedRequests,
		lastSeenAt,
		lastSeenAt,
		strings.TrimSpace(spiffeID),
	)
	if err != nil {
		return fmt.Errorf(
			"update workload risk %q: %w",
			spiffeID,
			err,
		)
	}

	return requireAffected(
		result,
		spiffeID,
		"update risk for",
	)
}

// Quarantine marks a workload as quarantined.
func (r *SQLiteWorkloadRepository) Quarantine(
	ctx context.Context,
	spiffeID string,
	score int,
	quarantinedAt time.Time,
) error {
	if err := validateContextAndWorkloadID(
		ctx,
		spiffeID,
	); err != nil {
		return err
	}

	if !domain.ReachesQuarantineThreshold(score) {
		return fmt.Errorf(
			"quarantine score must be at least %d",
			domain.QuarantineThreshold,
		)
	}

	if quarantinedAt.IsZero() {
		return errors.New(
			"quarantine timestamp must not be zero",
		)
	}

	quarantinedAt = quarantinedAt.UTC()

	result, err := r.db.ExecContext(
		ctx,
		`
			UPDATE workloads
			SET
				status = 'quarantined',
				risk_score = ?,
				quarantined_at = ?,
				last_seen_at = ?,
				updated_at = ?
			WHERE spiffe_id = ?
		`,
		score,
		quarantinedAt,
		quarantinedAt,
		quarantinedAt,
		strings.TrimSpace(spiffeID),
	)
	if err != nil {
		return fmt.Errorf(
			"quarantine workload %q: %w",
			spiffeID,
			err,
		)
	}

	return requireAffected(
		result,
		spiffeID,
		"quarantine",
	)
}

// Release returns a quarantined workload to active state.
func (r *SQLiteWorkloadRepository) Release(
	ctx context.Context,
	spiffeID string,
	releasedAt time.Time,
) error {
	if err := validateContextAndWorkloadID(
		ctx,
		spiffeID,
	); err != nil {
		return err
	}

	if releasedAt.IsZero() {
		return errors.New(
			"release timestamp must not be zero",
		)
	}

	releasedAt = releasedAt.UTC()

	result, err := r.db.ExecContext(
		ctx,
		`
			UPDATE workloads
			SET
				status = 'active',
				risk_score = 0,
				denied_requests = 0,
				quarantined_at = NULL,
				updated_at = ?
			WHERE spiffe_id = ?
			  AND status = 'quarantined'
		`,
		releasedAt,
		strings.TrimSpace(spiffeID),
	)
	if err != nil {
		return fmt.Errorf(
			"release workload %q: %w",
			spiffeID,
			err,
		)
	}

	return r.requireStatefulUpdate(
		ctx,
		result,
		spiffeID,
		"release",
	)
}

// ResetRisk clears risk fields only for an active workload.
func (r *SQLiteWorkloadRepository) ResetRisk(
	ctx context.Context,
	spiffeID string,
	resetAt time.Time,
) error {
	if err := validateContextAndWorkloadID(
		ctx,
		spiffeID,
	); err != nil {
		return err
	}

	if resetAt.IsZero() {
		return errors.New(
			"reset timestamp must not be zero",
		)
	}

	resetAt = resetAt.UTC()

	result, err := r.db.ExecContext(
		ctx,
		`
			UPDATE workloads
			SET
				risk_score = 0,
				denied_requests = 0,
				updated_at = ?
			WHERE spiffe_id = ?
			  AND status = 'active'
		`,
		resetAt,
		strings.TrimSpace(spiffeID),
	)
	if err != nil {
		return fmt.Errorf(
			"reset workload risk %q: %w",
			spiffeID,
			err,
		)
	}

	return r.requireStatefulUpdate(
		ctx,
		result,
		spiffeID,
		"reset risk for",
	)
}

func validateContextAndWorkloadID(
	ctx context.Context,
	spiffeID string,
) error {
	if ctx == nil {
		return errors.New(
			"context must not be nil",
		)
	}

	spiffeID = strings.TrimSpace(spiffeID)

	if !domain.IsKnownWorkloadID(spiffeID) {
		return fmt.Errorf(
			"unknown workload SPIFFE ID %q",
			spiffeID,
		)
	}

	return nil
}

func requireAffected(
	result sql.Result,
	spiffeID string,
	action string,
) error {
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf(
			"read affected rows while attempting to %s workload %q: %w",
			action,
			spiffeID,
			err,
		)
	}

	if affected == 0 {
		return fmt.Errorf(
			"%w: workload %q",
			ErrNotFound,
			spiffeID,
		)
	}

	return nil
}

func (r *SQLiteWorkloadRepository) requireStatefulUpdate(
	ctx context.Context,
	result sql.Result,
	spiffeID string,
	action string,
) error {
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf(
			"read affected rows while attempting to %s workload %q: %w",
			action,
			spiffeID,
			err,
		)
	}

	if affected > 0 {
		return nil
	}

	var status string

	err = r.db.QueryRowContext(
		ctx,
		`
			SELECT status
			FROM workloads
			WHERE spiffe_id = ?
		`,
		strings.TrimSpace(spiffeID),
	).Scan(&status)

	if errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf(
			"%w: workload %q",
			ErrNotFound,
			spiffeID,
		)
	}

	if err != nil {
		return fmt.Errorf(
			"read workload state %q: %w",
			spiffeID,
			err,
		)
	}

	return fmt.Errorf(
		"%w: cannot %s workload %q while status is %q",
		ErrInvalidState,
		action,
		spiffeID,
		status,
	)
}

type workloadScanner interface {
	Scan(dest ...any) error
}

func scanWorkload(
	scanner workloadScanner,
) (domain.Workload, error) {
	var (
		workload      domain.Workload
		status        string
		lastSeen      sql.NullTime
		quarantinedAt sql.NullTime
	)

	err := scanner.Scan(
		&workload.ID,
		&workload.Name,
		&workload.SPIFFEID,
		&status,
		&workload.RiskScore,
		&workload.DeniedRequests,
		&lastSeen,
		&quarantinedAt,
		&workload.CreatedAt,
		&workload.UpdatedAt,
	)
	if err != nil {
		return domain.Workload{}, err
	}

	workload.Status = domain.WorkloadStatus(
		status,
	)
	workload.CreatedAt = workload.CreatedAt.UTC()
	workload.UpdatedAt = workload.UpdatedAt.UTC()

	if lastSeen.Valid {
		value := lastSeen.Time.UTC()
		workload.LastSeenAt = &value
	}

	if quarantinedAt.Valid {
		value := quarantinedAt.Time.UTC()
		workload.QuarantinedAt = &value
	}

	if err = workload.Validate(); err != nil {
		return domain.Workload{}, fmt.Errorf(
			"validate stored workload: %w",
			err,
		)
	}

	return workload, nil
}
