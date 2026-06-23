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

// SQLiteIncidentRepository stores quarantine incidents and reasons.
type SQLiteIncidentRepository struct {
	db *sql.DB
}

// NewSQLiteIncidentRepository creates an incident repository.
func NewSQLiteIncidentRepository(
	db *sql.DB,
) (*SQLiteIncidentRepository, error) {
	if db == nil {
		return nil, errors.New(
			"database must not be nil",
		)
	}

	return &SQLiteIncidentRepository{
		db: db,
	}, nil
}

// Create opens a quarantine incident and stores all contributing reasons.
func (r *SQLiteIncidentRepository) Create(
	ctx context.Context,
	spiffeID string,
	score int,
	reasons []domain.RiskContribution,
	quarantinedAt time.Time,
) (domain.Incident, error) {
	if err := validateContextAndWorkloadID(
		ctx,
		spiffeID,
	); err != nil {
		return domain.Incident{}, err
	}

	if !domain.ReachesQuarantineThreshold(score) {
		return domain.Incident{}, fmt.Errorf(
			"incident score must be at least %d",
			domain.QuarantineThreshold,
		)
	}

	if quarantinedAt.IsZero() {
		return domain.Incident{}, errors.New(
			"quarantine timestamp must not be zero",
		)
	}

	if len(reasons) == 0 {
		return domain.Incident{}, errors.New(
			"incident must include at least one reason",
		)
	}

	for index, reason := range reasons {
		if err := reason.Validate(); err != nil {
			return domain.Incident{}, fmt.Errorf(
				"validate incident reason %d: %w",
				index,
				err,
			)
		}
	}

	quarantinedAt = quarantinedAt.UTC()

	transaction, err := r.db.BeginTx(
		ctx,
		nil,
	)
	if err != nil {
		return domain.Incident{}, fmt.Errorf(
			"begin incident transaction: %w",
			err,
		)
	}

	committed := false

	defer func() {
		if !committed {
			_ = transaction.Rollback()
		}
	}()

	workloadDatabaseID, workloadStatus, err :=
		findWorkloadState(
			ctx,
			transaction,
			spiffeID,
		)
	if err != nil {
		return domain.Incident{}, err
	}

	if workloadStatus !=
		string(domain.WorkloadStatusQuarantined) {
		return domain.Incident{}, fmt.Errorf(
			"%w: cannot create incident for workload %q while status is %q",
			ErrInvalidState,
			spiffeID,
			workloadStatus,
		)
	}

	result, err := transaction.ExecContext(
		ctx,
		`
			INSERT INTO incidents(
				workload_id,
				status,
				score_at_quarantine,
				quarantined_at,
				created_at,
				updated_at
			)
			VALUES (
				?,
				'open',
				?,
				?,
				?,
				?
			)
		`,
		workloadDatabaseID,
		score,
		quarantinedAt,
		quarantinedAt,
		quarantinedAt,
	)
	if err != nil {
		if isUniqueConstraintError(err) {
			return domain.Incident{}, fmt.Errorf(
				"%w: workload %q already has an open incident",
				ErrConflict,
				spiffeID,
			)
		}

		return domain.Incident{}, fmt.Errorf(
			"insert incident for workload %q: %w",
			spiffeID,
			err,
		)
	}

	incidentID, err := result.LastInsertId()
	if err != nil {
		return domain.Incident{}, fmt.Errorf(
			"read incident ID: %w",
			err,
		)
	}

	storedReasons := make(
		[]domain.IncidentReason,
		0,
		len(reasons),
	)

	for _, reason := range reasons {
		reasonResult, insertErr :=
			transaction.ExecContext(
				ctx,
				`
					INSERT INTO incident_reasons(
						incident_id,
						risk_contribution_id,
						rule,
						points,
						reason,
						created_at
					)
					VALUES (?, NULL, ?, ?, ?, ?)
				`,
				incidentID,
				string(reason.Rule),
				reason.Points,
				reason.Reason,
				quarantinedAt,
			)
		if insertErr != nil {
			return domain.Incident{}, fmt.Errorf(
				"insert reason %q for incident %d: %w",
				reason.Rule,
				incidentID,
				insertErr,
			)
		}

		reasonID, insertErr :=
			reasonResult.LastInsertId()
		if insertErr != nil {
			return domain.Incident{}, fmt.Errorf(
				"read incident-reason ID: %w",
				insertErr,
			)
		}

		storedReasons = append(
			storedReasons,
			domain.IncidentReason{
				ID:         reasonID,
				IncidentID: incidentID,
				Rule:       reason.Rule,
				Points:     reason.Points,
				Reason:     reason.Reason,
				CreatedAt:  quarantinedAt,
			},
		)
	}

	if err = transaction.Commit(); err != nil {
		return domain.Incident{}, fmt.Errorf(
			"commit incident transaction: %w",
			err,
		)
	}

	committed = true

	incident := domain.Incident{
		ID:                incidentID,
		WorkloadID:        strings.TrimSpace(spiffeID),
		Status:            domain.IncidentStatusOpen,
		ScoreAtQuarantine: score,
		QuarantinedAt:     quarantinedAt,
		CreatedAt:         quarantinedAt,
		UpdatedAt:         quarantinedAt,
		Reasons:           storedReasons,
	}

	if err = incident.Validate(); err != nil {
		return domain.Incident{}, fmt.Errorf(
			"validate created incident: %w",
			err,
		)
	}

	return incident, nil
}

// FindOpenByWorkload returns the active incident for one workload.
func (r *SQLiteIncidentRepository) FindOpenByWorkload(
	ctx context.Context,
	spiffeID string,
) (domain.Incident, error) {
	if err := validateContextAndWorkloadID(
		ctx,
		spiffeID,
	); err != nil {
		return domain.Incident{}, err
	}

	row := r.db.QueryRowContext(
		ctx,
		incidentSelectSQL+`
			WHERE w.spiffe_id = ?
			  AND i.status = 'open'
		`,
		strings.TrimSpace(spiffeID),
	)

	incident, err := scanIncident(row)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.Incident{}, fmt.Errorf(
			"%w: no open incident for workload %q",
			ErrNotFound,
			spiffeID,
		)
	}

	if err != nil {
		return domain.Incident{}, fmt.Errorf(
			"find open incident for workload %q: %w",
			spiffeID,
			err,
		)
	}

	incident.Reasons, err = listIncidentReasons(
		ctx,
		r.db,
		incident.ID,
	)
	if err != nil {
		return domain.Incident{}, err
	}

	if err = incident.Validate(); err != nil {
		return domain.Incident{}, fmt.Errorf(
			"validate open incident: %w",
			err,
		)
	}

	return incident, nil
}

// ListByWorkload returns the newest incidents for one workload.
func (r *SQLiteIncidentRepository) ListByWorkload(
	ctx context.Context,
	spiffeID string,
	limit int,
) ([]domain.Incident, error) {
	if err := validateContextAndWorkloadID(
		ctx,
		spiffeID,
	); err != nil {
		return nil, err
	}

	if limit <= 0 || limit > 200 {
		return nil, errors.New(
			"incident limit must be between 1 and 200",
		)
	}

	rows, err := r.db.QueryContext(
		ctx,
		incidentSelectSQL+`
			WHERE w.spiffe_id = ?
			ORDER BY
				i.quarantined_at DESC,
				i.id DESC
			LIMIT ?
		`,
		strings.TrimSpace(spiffeID),
		limit,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"list incidents for workload %q: %w",
			spiffeID,
			err,
		)
	}

	defer func() {
		_ = rows.Close()
	}()

	incidents := make(
		[]domain.Incident,
		0,
		limit,
	)

	for rows.Next() {
		incident, scanErr := scanIncident(rows)
		if scanErr != nil {
			return nil, fmt.Errorf(
				"scan incident: %w",
				scanErr,
			)
		}

		incident.Reasons, scanErr =
			listIncidentReasons(
				ctx,
				r.db,
				incident.ID,
			)
		if scanErr != nil {
			return nil, scanErr
		}

		if validationErr :=
			incident.Validate(); validationErr != nil {
			return nil, fmt.Errorf(
				"validate incident %d: %w",
				incident.ID,
				validationErr,
			)
		}

		incidents = append(
			incidents,
			incident,
		)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf(
			"iterate incidents: %w",
			err,
		)
	}

	return incidents, nil
}

// Release closes the currently open incident for a workload.
func (r *SQLiteIncidentRepository) Release(
	ctx context.Context,
	spiffeID string,
	releasedBy string,
	releasedAt time.Time,
) (domain.Incident, error) {
	if err := validateContextAndWorkloadID(
		ctx,
		spiffeID,
	); err != nil {
		return domain.Incident{}, err
	}

	releasedBy = strings.TrimSpace(releasedBy)

	if !domain.IsKnownWorkloadID(releasedBy) {
		return domain.Incident{}, fmt.Errorf(
			"unknown release actor SPIFFE ID %q",
			releasedBy,
		)
	}

	if releasedAt.IsZero() {
		return domain.Incident{}, errors.New(
			"release timestamp must not be zero",
		)
	}

	releasedAt = releasedAt.UTC()

	transaction, err := r.db.BeginTx(
		ctx,
		nil,
	)
	if err != nil {
		return domain.Incident{}, fmt.Errorf(
			"begin incident release transaction: %w",
			err,
		)
	}

	committed := false

	defer func() {
		if !committed {
			_ = transaction.Rollback()
		}
	}()

	row := transaction.QueryRowContext(
		ctx,
		incidentSelectSQL+`
			WHERE w.spiffe_id = ?
			  AND i.status = 'open'
		`,
		strings.TrimSpace(spiffeID),
	)

	incident, err := scanIncident(row)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.Incident{}, fmt.Errorf(
			"%w: no open incident for workload %q",
			ErrNotFound,
			spiffeID,
		)
	}

	if err != nil {
		return domain.Incident{}, fmt.Errorf(
			"find incident to release: %w",
			err,
		)
	}

	incident.Reasons, err = listIncidentReasons(
		ctx,
		transaction,
		incident.ID,
	)
	if err != nil {
		return domain.Incident{}, err
	}

	result, err := transaction.ExecContext(
		ctx,
		`
			UPDATE incidents
			SET
				status = 'released',
				released_at = ?,
				released_by = ?,
				updated_at = ?
			WHERE id = ?
			  AND status = 'open'
		`,
		releasedAt,
		releasedBy,
		releasedAt,
		incident.ID,
	)
	if err != nil {
		return domain.Incident{}, fmt.Errorf(
			"release incident %d: %w",
			incident.ID,
			err,
		)
	}

	affected, err := result.RowsAffected()
	if err != nil {
		return domain.Incident{}, fmt.Errorf(
			"read released incident rows: %w",
			err,
		)
	}

	if affected != 1 {
		return domain.Incident{}, fmt.Errorf(
			"%w: incident %d was not open",
			ErrInvalidState,
			incident.ID,
		)
	}

	if err = transaction.Commit(); err != nil {
		return domain.Incident{}, fmt.Errorf(
			"commit incident release: %w",
			err,
		)
	}

	committed = true

	incident.Status = domain.IncidentStatusReleased
	incident.ReleasedAt = &releasedAt
	incident.ReleasedBy = releasedBy
	incident.UpdatedAt = releasedAt

	if err = incident.Validate(); err != nil {
		return domain.Incident{}, fmt.Errorf(
			"validate released incident: %w",
			err,
		)
	}

	return incident, nil
}

const incidentSelectSQL = `
	SELECT
		i.id,
		w.spiffe_id,
		i.status,
		i.score_at_quarantine,
		i.quarantined_at,
		i.released_at,
		i.released_by,
		i.created_at,
		i.updated_at
	FROM incidents AS i
	INNER JOIN workloads AS w
		ON w.id = i.workload_id
`

type incidentScanner interface {
	Scan(dest ...any) error
}

func scanIncident(
	scanner incidentScanner,
) (domain.Incident, error) {
	var (
		incident   domain.Incident
		status     string
		releasedAt sql.NullTime
		releasedBy sql.NullString
	)

	err := scanner.Scan(
		&incident.ID,
		&incident.WorkloadID,
		&status,
		&incident.ScoreAtQuarantine,
		&incident.QuarantinedAt,
		&releasedAt,
		&releasedBy,
		&incident.CreatedAt,
		&incident.UpdatedAt,
	)
	if err != nil {
		return domain.Incident{}, err
	}

	incident.Status = domain.IncidentStatus(status)
	incident.QuarantinedAt =
		incident.QuarantinedAt.UTC()
	incident.CreatedAt =
		incident.CreatedAt.UTC()
	incident.UpdatedAt =
		incident.UpdatedAt.UTC()

	if releasedAt.Valid {
		value := releasedAt.Time.UTC()
		incident.ReleasedAt = &value
	}

	if releasedBy.Valid {
		incident.ReleasedBy = releasedBy.String
	}

	return incident, nil
}

type incidentQueryer interface {
	QueryContext(
		context.Context,
		string,
		...any,
	) (*sql.Rows, error)
}

func listIncidentReasons(
	ctx context.Context,
	queryer incidentQueryer,
	incidentID int64,
) ([]domain.IncidentReason, error) {
	rows, err := queryer.QueryContext(
		ctx,
		`
			SELECT
				id,
				incident_id,
				risk_contribution_id,
				rule,
				points,
				reason,
				created_at
			FROM incident_reasons
			WHERE incident_id = ?
			ORDER BY id
		`,
		incidentID,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"list reasons for incident %d: %w",
			incidentID,
			err,
		)
	}

	defer func() {
		_ = rows.Close()
	}()

	reasons := make(
		[]domain.IncidentReason,
		0,
	)

	for rows.Next() {
		var (
			reason             domain.IncidentReason
			riskContributionID sql.NullInt64
			rule               string
		)

		if err = rows.Scan(
			&reason.ID,
			&reason.IncidentID,
			&riskContributionID,
			&rule,
			&reason.Points,
			&reason.Reason,
			&reason.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf(
				"scan reason for incident %d: %w",
				incidentID,
				err,
			)
		}

		reason.Rule = domain.RiskRule(rule)
		reason.CreatedAt = reason.CreatedAt.UTC()

		if riskContributionID.Valid {
			value := riskContributionID.Int64
			reason.RiskContributionID = &value
		}

		reasons = append(
			reasons,
			reason,
		)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf(
			"iterate reasons for incident %d: %w",
			incidentID,
			err,
		)
	}

	return reasons, nil
}

func findWorkloadState(
	ctx context.Context,
	transaction *sql.Tx,
	spiffeID string,
) (int64, string, error) {
	var (
		workloadID int64
		status     string
	)

	err := transaction.QueryRowContext(
		ctx,
		`
			SELECT
				id,
				status
			FROM workloads
			WHERE spiffe_id = ?
		`,
		strings.TrimSpace(spiffeID),
	).Scan(
		&workloadID,
		&status,
	)

	if errors.Is(err, sql.ErrNoRows) {
		return 0, "", fmt.Errorf(
			"%w: workload %q has not been registered",
			ErrNotFound,
			spiffeID,
		)
	}

	if err != nil {
		return 0, "", fmt.Errorf(
			"find workload state %q: %w",
			spiffeID,
			err,
		)
	}

	return workloadID, status, nil
}

func isUniqueConstraintError(
	err error,
) bool {
	if err == nil {
		return false
	}

	message := strings.ToLower(
		err.Error(),
	)

	return strings.Contains(
		message,
		"unique constraint failed",
	)
}
