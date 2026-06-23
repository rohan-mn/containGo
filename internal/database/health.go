package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
)

// CheckHealth verifies that SQLite is reachable, internally consistent,
// and enforcing foreign-key constraints.
func CheckHealth(
	ctx context.Context,
	db *sql.DB,
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

	if db == nil {
		return errors.New(
			"database must not be nil",
		)
	}

	if err := db.PingContext(ctx); err != nil {
		return fmt.Errorf(
			"ping database: %w",
			err,
		)
	}

	var foreignKeysEnabled int

	if err := db.QueryRowContext(
		ctx,
		`PRAGMA foreign_keys`,
	).Scan(
		&foreignKeysEnabled,
	); err != nil {
		return fmt.Errorf(
			"read SQLite foreign-key setting: %w",
			err,
		)
	}

	if foreignKeysEnabled != 1 {
		return errors.New(
			"SQLite foreign-key enforcement is disabled",
		)
	}

	var integrityResult string

	if err := db.QueryRowContext(
		ctx,
		`PRAGMA quick_check`,
	).Scan(
		&integrityResult,
	); err != nil {
		return fmt.Errorf(
			"run SQLite integrity check: %w",
			err,
		)
	}

	if !strings.EqualFold(
		strings.TrimSpace(integrityResult),
		"ok",
	) {
		return fmt.Errorf(
			"SQLite integrity check failed: %s",
			integrityResult,
		)
	}

	return nil
}
