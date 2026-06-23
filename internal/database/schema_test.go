package database_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"containgo.local/containgo/internal/database"
	"containgo.local/containgo/internal/testutil"
)

func TestVerifySchema(
	t *testing.T,
) {
	db := testutil.OpenSQLite(t)

	if err := database.VerifySchema(
		context.Background(),
		db,
	); err != nil {
		t.Fatalf(
			"VerifySchema() error: %v",
			err,
		)
	}
}

func TestVerifySchemaDetectsMissingTable(
	t *testing.T,
) {
	db := testutil.OpenSQLite(t)

	_, err := db.Exec(
		`DROP TABLE audit_log`,
	)
	if err != nil {
		t.Fatalf(
			"DROP TABLE audit_log error: %v",
			err,
		)
	}

	err = database.VerifySchema(
		context.Background(),
		db,
	)
	if err == nil {
		t.Fatal(
			"VerifySchema() returned nil error after dropping audit_log",
		)
	}

	if !strings.Contains(
		err.Error(),
		"audit_log",
	) {
		t.Fatalf(
			"VerifySchema() error = %q, want audit_log",
			err,
		)
	}
}

func TestVerifySchemaRejectsNilDatabase(
	t *testing.T,
) {
	err := database.VerifySchema(
		context.Background(),
		nil,
	)

	if err == nil {
		t.Fatal(
			"VerifySchema(nil) returned nil error",
		)
	}

	if !strings.Contains(
		err.Error(),
		"database must not be nil",
	) {
		t.Fatalf(
			"VerifySchema(nil) error = %q",
			err,
		)
	}
}

func TestVerifySchemaRejectsCancelledContext(
	t *testing.T,
) {
	db := testutil.OpenSQLite(t)

	ctx, cancel := context.WithCancel(
		context.Background(),
	)
	cancel()

	err := database.VerifySchema(
		ctx,
		db,
	)

	if !errors.Is(
		err,
		context.Canceled,
	) {
		t.Fatalf(
			"VerifySchema(cancelled context) error = %v, want context.Canceled",
			err,
		)
	}
}
