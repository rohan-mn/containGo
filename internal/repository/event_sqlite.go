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

// SQLiteEventRepository stores security events and risk contributions.
type SQLiteEventRepository struct {
	db *sql.DB
}

// NewSQLiteEventRepository creates an event repository.
func NewSQLiteEventRepository(
	db *sql.DB,
) (*SQLiteEventRepository, error) {
	if db == nil {
		return nil, errors.New(
			"database must not be nil",
		)
	}

	return &SQLiteEventRepository{
		db: db,
	}, nil
}

// ExistsByRequestID reports whether a security event has already been stored.
func (r *SQLiteEventRepository) ExistsByRequestID(
	ctx context.Context,
	requestID string,
) (bool, error) {
	if ctx == nil {
		return false, errors.New(
			"context must not be nil",
		)
	}

	requestID = strings.TrimSpace(requestID)
	if requestID == "" {
		return false, errors.New(
			"request ID must not be empty",
		)
	}

	var found int

	err := r.db.QueryRowContext(
		ctx,
		`
			SELECT 1
			FROM security_events
			WHERE request_id = ?
		`,
		requestID,
	).Scan(&found)

	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}

	if err != nil {
		return false, fmt.Errorf(
			"check security event request ID %q: %w",
			requestID,
			err,
		)
	}

	return true, nil
}

// Create atomically stores an event and all associated risk contributions.
func (r *SQLiteEventRepository) Create(
	ctx context.Context,
	event domain.SecurityEvent,
	contributions []domain.RiskContribution,
	createdAt time.Time,
) (domain.StoredEvent, error) {
	if ctx == nil {
		return domain.StoredEvent{}, errors.New(
			"context must not be nil",
		)
	}

	if event.ID != 0 {
		return domain.StoredEvent{}, errors.New(
			"event ID must be zero before creation",
		)
	}

	if err := event.Validate(); err != nil {
		return domain.StoredEvent{}, fmt.Errorf(
			"validate security event: %w",
			err,
		)
	}

	if !domain.IsKnownWorkloadID(event.WorkloadID) {
		return domain.StoredEvent{}, fmt.Errorf(
			"unknown workload SPIFFE ID %q",
			event.WorkloadID,
		)
	}

	if createdAt.IsZero() {
		return domain.StoredEvent{}, errors.New(
			"created-at timestamp must not be zero",
		)
	}

	for index, contribution := range contributions {
		if err := contribution.Validate(); err != nil {
			return domain.StoredEvent{}, fmt.Errorf(
				"validate contribution %d: %w",
				index,
				err,
			)
		}
	}

	createdAt = createdAt.UTC()
	event.OccurredAt = event.OccurredAt.UTC()

	transaction, err := r.db.BeginTx(
		ctx,
		nil,
	)
	if err != nil {
		return domain.StoredEvent{}, fmt.Errorf(
			"begin event transaction: %w",
			err,
		)
	}

	committed := false

	defer func() {
		if !committed {
			_ = transaction.Rollback()
		}
	}()

	workloadDatabaseID, err := findWorkloadDatabaseID(
		ctx,
		transaction,
		event.WorkloadID,
	)
	if err != nil {
		return domain.StoredEvent{}, err
	}

	result, err := transaction.ExecContext(
		ctx,
		`
			INSERT INTO security_events(
				request_id,
				workload_id,
				method,
				path,
				decision,
				status_code,
				reason,
				occurred_at,
				created_at
			)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT(request_id) DO NOTHING
		`,
		event.RequestID,
		workloadDatabaseID,
		event.Method,
		event.Path,
		string(event.Decision),
		event.StatusCode,
		nullableReason(event.Reason),
		event.OccurredAt,
		createdAt,
	)
	if err != nil {
		return domain.StoredEvent{}, fmt.Errorf(
			"insert security event %q: %w",
			event.RequestID,
			err,
		)
	}

	affected, err := result.RowsAffected()
	if err != nil {
		return domain.StoredEvent{}, fmt.Errorf(
			"read security-event affected rows: %w",
			err,
		)
	}

	if affected == 0 {
		return domain.StoredEvent{}, fmt.Errorf(
			"%w: request ID %q already exists",
			ErrConflict,
			event.RequestID,
		)
	}

	eventID, err := result.LastInsertId()
	if err != nil {
		return domain.StoredEvent{}, fmt.Errorf(
			"read security-event ID: %w",
			err,
		)
	}

	for _, contribution := range contributions {
		_, err = transaction.ExecContext(
			ctx,
			`
				INSERT INTO risk_contributions(
					security_event_id,
					workload_id,
					rule,
					points,
					reason,
					created_at
				)
				VALUES (?, ?, ?, ?, ?, ?)
			`,
			eventID,
			workloadDatabaseID,
			string(contribution.Rule),
			contribution.Points,
			contribution.Reason,
			createdAt,
		)
		if err != nil {
			return domain.StoredEvent{}, fmt.Errorf(
				"insert contribution %q for event %q: %w",
				contribution.Rule,
				event.RequestID,
				err,
			)
		}
	}

	if err = transaction.Commit(); err != nil {
		return domain.StoredEvent{}, fmt.Errorf(
			"commit event transaction: %w",
			err,
		)
	}

	committed = true
	event.ID = eventID

	stored := domain.StoredEvent{
		Event: event,
		Contributions: append(
			[]domain.RiskContribution(nil),
			contributions...,
		),
		CreatedAt: createdAt,
	}

	if err = stored.Validate(); err != nil {
		return domain.StoredEvent{}, fmt.Errorf(
			"validate stored event: %w",
			err,
		)
	}

	return stored, nil
}

// ListByWorkload returns the newest persisted events for one workload.
func (r *SQLiteEventRepository) ListByWorkload(
	ctx context.Context,
	spiffeID string,
	limit int,
) ([]domain.StoredEvent, error) {
	if err := validateContextAndWorkloadID(
		ctx,
		spiffeID,
	); err != nil {
		return nil, err
	}

	if limit <= 0 || limit > 500 {
		return nil, errors.New(
			"event limit must be between 1 and 500",
		)
	}

	rows, err := r.db.QueryContext(
		ctx,
		`
			SELECT
				se.id,
				se.request_id,
				w.spiffe_id,
				se.method,
				se.path,
				se.decision,
				se.status_code,
				se.reason,
				se.occurred_at,
				se.created_at
			FROM security_events AS se
			INNER JOIN workloads AS w
				ON w.id = se.workload_id
			WHERE w.spiffe_id = ?
			ORDER BY
				se.occurred_at DESC,
				se.id DESC
			LIMIT ?
		`,
		strings.TrimSpace(spiffeID),
		limit,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"list events for workload %q: %w",
			spiffeID,
			err,
		)
	}

	defer func() {
		_ = rows.Close()
	}()

	events := make(
		[]domain.StoredEvent,
		0,
		limit,
	)

	for rows.Next() {
		stored, scanErr := scanStoredEvent(rows)
		if scanErr != nil {
			return nil, fmt.Errorf(
				"scan security event: %w",
				scanErr,
			)
		}

		contributions, contributionErr :=
			r.listContributions(
				ctx,
				stored.Event.ID,
			)
		if contributionErr != nil {
			return nil, contributionErr
		}

		stored.Contributions = contributions

		if validationErr := stored.Validate(); validationErr != nil {
			return nil, fmt.Errorf(
				"validate stored event %d: %w",
				stored.Event.ID,
				validationErr,
			)
		}

		events = append(
			events,
			stored,
		)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf(
			"iterate security events: %w",
			err,
		)
	}

	return events, nil
}

// CountDeniedSince counts denied requests from since onward.
func (r *SQLiteEventRepository) CountDeniedSince(
	ctx context.Context,
	spiffeID string,
	since time.Time,
) (int, error) {
	if err := validateContextAndWorkloadID(
		ctx,
		spiffeID,
	); err != nil {
		return 0, err
	}

	if since.IsZero() {
		return 0, errors.New(
			"since timestamp must not be zero",
		)
	}

	var count int

	err := r.db.QueryRowContext(
		ctx,
		`
			SELECT COUNT(*)
			FROM security_events AS se
			INNER JOIN workloads AS w
				ON w.id = se.workload_id
			WHERE w.spiffe_id = ?
			  AND se.decision = 'denied'
			  AND se.occurred_at >= ?
		`,
		strings.TrimSpace(spiffeID),
		since.UTC(),
	).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf(
			"count denied events for workload %q: %w",
			spiffeID,
			err,
		)
	}

	return count, nil
}

func (r *SQLiteEventRepository) listContributions(
	ctx context.Context,
	eventID int64,
) ([]domain.RiskContribution, error) {
	rows, err := r.db.QueryContext(
		ctx,
		`
			SELECT
				rule,
				points,
				reason
			FROM risk_contributions
			WHERE security_event_id = ?
			ORDER BY id
		`,
		eventID,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"list contributions for event %d: %w",
			eventID,
			err,
		)
	}

	defer func() {
		_ = rows.Close()
	}()

	contributions := make(
		[]domain.RiskContribution,
		0,
	)

	for rows.Next() {
		var (
			contribution domain.RiskContribution
			rule         string
		)

		if err = rows.Scan(
			&rule,
			&contribution.Points,
			&contribution.Reason,
		); err != nil {
			return nil, fmt.Errorf(
				"scan contribution for event %d: %w",
				eventID,
				err,
			)
		}

		contribution.Rule = domain.RiskRule(rule)

		if err = contribution.Validate(); err != nil {
			return nil, fmt.Errorf(
				"validate stored contribution: %w",
				err,
			)
		}

		contributions = append(
			contributions,
			contribution,
		)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf(
			"iterate contributions for event %d: %w",
			eventID,
			err,
		)
	}

	return contributions, nil
}

func findWorkloadDatabaseID(
	ctx context.Context,
	transaction *sql.Tx,
	spiffeID string,
) (int64, error) {
	var workloadID int64

	err := transaction.QueryRowContext(
		ctx,
		`
			SELECT id
			FROM workloads
			WHERE spiffe_id = ?
		`,
		strings.TrimSpace(spiffeID),
	).Scan(&workloadID)

	if errors.Is(err, sql.ErrNoRows) {
		return 0, fmt.Errorf(
			"%w: workload %q has not been registered",
			ErrNotFound,
			spiffeID,
		)
	}

	if err != nil {
		return 0, fmt.Errorf(
			"find workload database ID %q: %w",
			spiffeID,
			err,
		)
	}

	return workloadID, nil
}

func nullableReason(
	reason string,
) any {
	reason = strings.TrimSpace(reason)

	if reason == "" {
		return nil
	}

	return reason
}

type storedEventScanner interface {
	Scan(dest ...any) error
}

func scanStoredEvent(
	scanner storedEventScanner,
) (domain.StoredEvent, error) {
	var (
		stored   domain.StoredEvent
		decision string
		reason   sql.NullString
	)

	err := scanner.Scan(
		&stored.Event.ID,
		&stored.Event.RequestID,
		&stored.Event.WorkloadID,
		&stored.Event.Method,
		&stored.Event.Path,
		&decision,
		&stored.Event.StatusCode,
		&reason,
		&stored.Event.OccurredAt,
		&stored.CreatedAt,
	)
	if err != nil {
		return domain.StoredEvent{}, err
	}

	stored.Event.Decision = domain.SecurityDecision(
		decision,
	)

	if reason.Valid {
		stored.Event.Reason = reason.String
	}

	stored.Event.OccurredAt =
		stored.Event.OccurredAt.UTC()
	stored.CreatedAt = stored.CreatedAt.UTC()

	return stored, nil
}
