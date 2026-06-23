package database_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"containgo.local/containgo/internal/database"
	"containgo.local/containgo/internal/testutil"
)

func TestCheckHealth(
	t *testing.T,
) {
	db := testutil.OpenSQLite(t)

	if err := database.CheckHealth(
		context.Background(),
		db,
	); err != nil {
		t.Fatalf(
			"CheckHealth() error: %v",
			err,
		)
	}
}

func TestCheckHealthRejectsNilDatabase(
	t *testing.T,
) {
	err := database.CheckHealth(
		context.Background(),
		nil,
	)

	if err == nil {
		t.Fatal(
			"CheckHealth(nil) returned nil error",
		)
	}

	if !strings.Contains(
		err.Error(),
		"database must not be nil",
	) {
		t.Fatalf(
			"CheckHealth(nil) error = %q",
			err,
		)
	}
}

func TestCheckHealthRejectsNilContext(
	t *testing.T,
) {
	db := testutil.OpenSQLite(t)

	err := database.CheckHealth(
		nil,
		db,
	)

	if err == nil {
		t.Fatal(
			"CheckHealth(nil context) returned nil error",
		)
	}

	if !strings.Contains(
		err.Error(),
		"context must not be nil",
	) {
		t.Fatalf(
			"CheckHealth(nil context) error = %q",
			err,
		)
	}
}

func TestCheckHealthRejectsCancelledContext(
	t *testing.T,
) {
	db := testutil.OpenSQLite(t)

	ctx, cancel := context.WithCancel(
		context.Background(),
	)
	cancel()

	err := database.CheckHealth(
		ctx,
		db,
	)

	if !errors.Is(
		err,
		context.Canceled,
	) {
		t.Fatalf(
			"CheckHealth(cancelled context) error = %v, want context.Canceled",
			err,
		)
	}
}
