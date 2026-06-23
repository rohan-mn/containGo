package repository

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"containgo.local/containgo/internal/domain"
)

// SQLiteAuditRepository stores immutable security audit records.
type SQLiteAuditRepository struct {
	db *sql.DB
}

// NewSQLiteAuditRepository creates an audit repository.
func NewSQLiteAuditRepository(
	db *sql.DB,
) (*SQLiteAuditRepository, error) {
	if db == nil {
		return nil, errors.New(
			"database must not be nil",
		)
	}

	return &SQLiteAuditRepository{
		db: db,
	}, nil
}

// Create inserts one immutable audit record.
func (r *SQLiteAuditRepository) Create(
	ctx context.Context,
	record domain.AuditRecord,
) (domain.AuditRecord, error) {
	if err := validateAuditContext(ctx); err != nil {
		return domain.AuditRecord{}, err
	}

	if record.ID != 0 {
		return domain.AuditRecord{}, errors.New(
			"new audit record ID must be zero",
		)
	}

	record.ActorSPIFFEID = strings.TrimSpace(
		record.ActorSPIFFEID,
	)
	record.TargetSPIFFEID = strings.TrimSpace(
		record.TargetSPIFFEID,
	)
	record.DetailsJSON = append(
		json.RawMessage(nil),
		bytes.TrimSpace(record.DetailsJSON)...,
	)

	if !record.OccurredAt.IsZero() {
		record.OccurredAt = record.OccurredAt.UTC()
	}

	if err := record.Validate(); err != nil {
		return domain.AuditRecord{}, fmt.Errorf(
			"validate audit record: %w",
			err,
		)
	}

	var compactDetails bytes.Buffer

	if err := json.Compact(
		&compactDetails,
		record.DetailsJSON,
	); err != nil {
		return domain.AuditRecord{}, fmt.Errorf(
			"compact audit details JSON: %w",
			err,
		)
	}

	record.DetailsJSON = append(
		json.RawMessage(nil),
		compactDetails.Bytes()...,
	)

	transaction, err := r.db.BeginTx(
		ctx,
		nil,
	)
	if err != nil {
		return domain.AuditRecord{}, fmt.Errorf(
			"begin audit transaction: %w",
			err,
		)
	}

	committed := false

	defer func() {
		if !committed {
			_ = transaction.Rollback()
		}
	}()

	// Confirm that the audit actor is a registered workload.
	if _, _, err = findWorkloadState(
		ctx,
		transaction,
		record.ActorSPIFFEID,
	); err != nil {
		return domain.AuditRecord{}, fmt.Errorf(
			"find audit actor: %w",
			err,
		)
	}

	var targetSPIFFEID any

	// The target is optional, but when supplied it must be registered.
	if record.TargetSPIFFEID != "" {
		if _, _, err = findWorkloadState(
			ctx,
			transaction,
			record.TargetSPIFFEID,
		); err != nil {
			return domain.AuditRecord{}, fmt.Errorf(
				"find audit target: %w",
				err,
			)
		}

		targetSPIFFEID = record.TargetSPIFFEID
	}

	result, err := transaction.ExecContext(
		ctx,
		`
		INSERT INTO audit_log(
			actor_spiffe_id,
			action,
			target_spiffe_id,
			details_json,
			occurred_at
		)
		VALUES (?, ?, ?, ?, ?)
	`,
		record.ActorSPIFFEID,
		string(record.Action),
		targetSPIFFEID,
		string(record.DetailsJSON),
		record.OccurredAt,
	)
	if err != nil {
		return domain.AuditRecord{}, fmt.Errorf(
			"insert audit record: %w",
			err,
		)
	}

	recordID, err := result.LastInsertId()
	if err != nil {
		return domain.AuditRecord{}, fmt.Errorf(
			"read audit record ID: %w",
			err,
		)
	}

	record.ID = recordID

	if err = record.Validate(); err != nil {
		return domain.AuditRecord{}, fmt.Errorf(
			"validate stored audit record: %w",
			err,
		)
	}

	if err = transaction.Commit(); err != nil {
		return domain.AuditRecord{}, fmt.Errorf(
			"commit audit transaction: %w",
			err,
		)
	}

	committed = true

	return record, nil
}

// ListRecent returns the newest audit records.
func (r *SQLiteAuditRepository) ListRecent(
	ctx context.Context,
	limit int,
) ([]domain.AuditRecord, error) {
	if err := validateAuditContext(ctx); err != nil {
		return nil, err
	}

	if err := validateAuditLimit(limit); err != nil {
		return nil, err
	}

	rows, err := r.db.QueryContext(
		ctx,
		auditSelectSQL+`
			ORDER BY
				a.occurred_at DESC,
				a.id DESC
			LIMIT ?
		`,
		limit,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"list recent audit records: %w",
			err,
		)
	}

	return collectAuditRecords(
		rows,
		limit,
	)
}

// ListByTarget returns the newest audit records for one target workload.
func (r *SQLiteAuditRepository) ListByTarget(
	ctx context.Context,
	targetSPIFFEID string,
	limit int,
) ([]domain.AuditRecord, error) {
	if err := validateContextAndWorkloadID(
		ctx,
		targetSPIFFEID,
	); err != nil {
		return nil, err
	}

	if err := validateAuditLimit(limit); err != nil {
		return nil, err
	}

	targetSPIFFEID = strings.TrimSpace(
		targetSPIFFEID,
	)

	rows, err := r.db.QueryContext(
		ctx,
		auditSelectSQL+`
			WHERE a.target_spiffe_id = ?
			ORDER BY
				a.occurred_at DESC,
				a.id DESC
			LIMIT ?
		`,
		targetSPIFFEID,
		limit,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"list audit records for target %q: %w",
			targetSPIFFEID,
			err,
		)
	}

	return collectAuditRecords(
		rows,
		limit,
	)
}

const auditSelectSQL = `
	SELECT
		a.id,
		a.actor_spiffe_id,
		a.action,
		a.target_spiffe_id,
		a.details_json,
		a.occurred_at
	FROM audit_log AS a
`

type auditScanner interface {
	Scan(dest ...any) error
}

func scanAuditRecord(
	scanner auditScanner,
) (domain.AuditRecord, error) {
	var (
		record            domain.AuditRecord
		action            string
		targetSPIFFEID    sql.NullString
		detailsJSONString string
	)

	err := scanner.Scan(
		&record.ID,
		&record.ActorSPIFFEID,
		&action,
		&targetSPIFFEID,
		&detailsJSONString,
		&record.OccurredAt,
	)
	if err != nil {
		return domain.AuditRecord{}, err
	}

	record.Action = domain.AuditAction(action)
	record.DetailsJSON = json.RawMessage(
		detailsJSONString,
	)
	record.OccurredAt = record.OccurredAt.UTC()

	if targetSPIFFEID.Valid {
		record.TargetSPIFFEID =
			targetSPIFFEID.String
	}

	return record, nil
}

func collectAuditRecords(
	rows *sql.Rows,
	capacity int,
) ([]domain.AuditRecord, error) {
	defer func() {
		_ = rows.Close()
	}()

	records := make(
		[]domain.AuditRecord,
		0,
		capacity,
	)

	for rows.Next() {
		record, err := scanAuditRecord(rows)
		if err != nil {
			return nil, fmt.Errorf(
				"scan audit record: %w",
				err,
			)
		}

		if err = record.Validate(); err != nil {
			return nil, fmt.Errorf(
				"validate audit record %d: %w",
				record.ID,
				err,
			)
		}

		records = append(
			records,
			record,
		)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf(
			"iterate audit records: %w",
			err,
		)
	}

	return records, nil
}

func validateAuditContext(
	ctx context.Context,
) error {
	if ctx == nil {
		return errors.New(
			"context must not be nil",
		)
	}

	if err := ctx.Err(); err != nil {
		return fmt.Errorf(
			"context is not usable: %w",
			err,
		)
	}

	return nil
}

func validateAuditLimit(
	limit int,
) error {
	if limit <= 0 || limit > 200 {
		return errors.New(
			"audit limit must be between 1 and 200",
		)
	}

	return nil
}
