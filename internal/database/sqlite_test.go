package database

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"containgo.local/containgo/migrations"
)

func TestOpenCreatesDatabaseAndSchema(
	t *testing.T,
) {
	databasePath := filepath.Join(
		t.TempDir(),
		"nested",
		"containgo.db",
	)

	db, err := Open(
		context.Background(),
		databasePath,
	)
	if err != nil {
		t.Fatalf(
			"Open() unexpected error: %v",
			err,
		)
	}

	t.Cleanup(func() {
		if closeErr := db.Close(); closeErr != nil {
			t.Errorf(
				"Close() unexpected error: %v",
				closeErr,
			)
		}
	})

	wantTables := []string{
		"audit_log",
		"incident_reasons",
		"incidents",
		"risk_contributions",
		"schema_migrations",
		"security_events",
		"workloads",
	}

	gotTables := readTableNames(
		t,
		db,
	)

	if !slices.Equal(
		gotTables,
		wantTables,
	) {
		t.Fatalf(
			"tables = %v, want %v",
			gotTables,
			wantTables,
		)
	}

	var migrationCount int

	err = db.QueryRow(
		`
			SELECT COUNT(*)
			FROM schema_migrations
		`,
	).Scan(&migrationCount)
	if err != nil {
		t.Fatalf(
			"count migrations: %v",
			err,
		)
	}

	if migrationCount != 1 {
		t.Fatalf(
			"migration count = %d, want 1",
			migrationCount,
		)
	}

	var foreignKeys int

	err = db.QueryRow(
		`PRAGMA foreign_keys`,
	).Scan(&foreignKeys)
	if err != nil {
		t.Fatalf(
			"read foreign_keys pragma: %v",
			err,
		)
	}

	if foreignKeys != 1 {
		t.Fatalf(
			"foreign_keys = %d, want 1",
			foreignKeys,
		)
	}

	var journalMode string

	err = db.QueryRow(
		`PRAGMA journal_mode`,
	).Scan(&journalMode)
	if err != nil {
		t.Fatalf(
			"read journal_mode pragma: %v",
			err,
		)
	}

	if !strings.EqualFold(
		journalMode,
		"wal",
	) {
		t.Fatalf(
			"journal_mode = %q, want wal",
			journalMode,
		)
	}
}

func TestMigrationsAreIdempotent(
	t *testing.T,
) {
	db := openTestDatabase(t)

	err := migrations.Apply(
		context.Background(),
		db,
	)
	if err != nil {
		t.Fatalf(
			"second Apply() unexpected error: %v",
			err,
		)
	}

	var migrationCount int

	err = db.QueryRow(
		`
			SELECT COUNT(*)
			FROM schema_migrations
		`,
	).Scan(&migrationCount)
	if err != nil {
		t.Fatalf(
			"count migrations: %v",
			err,
		)
	}

	if migrationCount != 1 {
		t.Fatalf(
			"migration count = %d, want 1",
			migrationCount,
		)
	}
}

func TestSchemaEnforcesConstraints(
	t *testing.T,
) {
	db := openTestDatabase(t)
	now := time.Now().UTC()

	_, err := db.Exec(
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
				'disabled',
				0,
				0,
				?,
				?
			)
		`,
		"invalid",
		"spiffe://containgo.local/invalid",
		now,
		now,
	)
	if err == nil {
		t.Fatal(
			"invalid workload status was accepted",
		)
	}

	result, err := db.Exec(
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
		`,
		"report-client",
		"spiffe://containgo.local/ns/containgo/sa/report-client",
		now,
		now,
	)
	if err != nil {
		t.Fatalf(
			"insert valid workload: %v",
			err,
		)
	}

	workloadID, err := result.LastInsertId()
	if err != nil {
		t.Fatalf(
			"read workload ID: %v",
			err,
		)
	}

	_, err = db.Exec(
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
			VALUES (
				?,
				?,
				'GET',
				'/api/reports',
				'denied',
				403,
				?,
				?,
				?
			)
		`,
		"req-valid",
		workloadID,
		"denied by policy",
		now,
		now,
	)
	if err != nil {
		t.Fatalf(
			"insert valid security event: %v",
			err,
		)
	}

	_, err = db.Exec(
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
			VALUES (
				?,
				?,
				'GET',
				'/api/reports',
				'denied',
				403,
				?,
				?,
				?
			)
		`,
		"req-invalid-foreign-key",
		workloadID+999,
		"denied by policy",
		now,
		now,
	)
	if err == nil {
		t.Fatal(
			"security event with invalid workload ID was accepted",
		)
	}

	_, err = db.Exec(
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
			VALUES (
				?,
				?,
				'GET',
				'/api/reports',
				'denied',
				403,
				NULL,
				?,
				?
			)
		`,
		"req-missing-reason",
		workloadID,
		now,
		now,
	)
	if err == nil {
		t.Fatal(
			"denied event without reason was accepted",
		)
	}
}

func TestOpenValidation(
	t *testing.T,
) {
	_, err := Open(
		context.Background(),
		" ",
	)
	if err == nil {
		t.Fatal(
			"Open(empty path) error = nil, want error",
		)
	}

	_, err = Open(
		nil,
		filepath.Join(
			t.TempDir(),
			"containgo.db",
		),
	)
	if err == nil {
		t.Fatal(
			"Open(nil context) error = nil, want error",
		)
	}

	ctx, cancel := context.WithCancel(
		context.Background(),
	)
	cancel()

	db, err := Open(
		ctx,
		filepath.Join(
			t.TempDir(),
			"cancelled.db",
		),
	)

	if db != nil {
		_ = db.Close()
	}

	if err == nil {
		t.Fatal(
			"Open(cancelled context) error = nil, want error",
		)
	}

	if !errors.Is(
		err,
		context.Canceled,
	) &&
		!strings.Contains(
			err.Error(),
			"context canceled",
		) {
		t.Fatalf(
			"Open(cancelled context) error = %v, want cancellation",
			err,
		)
	}
}

func openTestDatabase(
	t *testing.T,
) *sql.DB {
	t.Helper()

	databasePath := filepath.Join(
		t.TempDir(),
		"containgo.db",
	)

	db, err := Open(
		context.Background(),
		databasePath,
	)
	if err != nil {
		t.Fatalf(
			"Open() unexpected error: %v",
			err,
		)
	}

	t.Cleanup(func() {
		if closeErr := db.Close(); closeErr != nil {
			t.Errorf(
				"Close() unexpected error: %v",
				closeErr,
			)
		}
	})

	return db
}

func readTableNames(
	t *testing.T,
	db *sql.DB,
) []string {
	t.Helper()

	rows, err := db.Query(
		`
			SELECT name
			FROM sqlite_master
			WHERE type = 'table'
			  AND name NOT LIKE 'sqlite_%'
			ORDER BY name
		`,
	)
	if err != nil {
		t.Fatalf(
			"query table names: %v",
			err,
		)
	}

	defer func() {
		if closeErr := rows.Close(); closeErr != nil {
			t.Errorf(
				"close rows: %v",
				closeErr,
			)
		}
	}()

	var names []string

	for rows.Next() {
		var name string

		if err = rows.Scan(&name); err != nil {
			t.Fatalf(
				"scan table name: %v",
				err,
			)
		}

		names = append(
			names,
			name,
		)
	}

	if err = rows.Err(); err != nil {
		t.Fatalf(
			"iterate table names: %v",
			err,
		)
	}

	return names
}
