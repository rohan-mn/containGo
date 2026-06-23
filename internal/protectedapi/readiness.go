package protectedapi

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	databasecheck "containgo.local/containgo/internal/database"
)

// DatabaseReadinessChecker verifies the SQLite connection and schema.
type DatabaseReadinessChecker struct {
	db *sql.DB
}

// NewDatabaseReadinessChecker creates the readiness checker.
func NewDatabaseReadinessChecker(
	db *sql.DB,
) (*DatabaseReadinessChecker, error) {
	if db == nil {
		return nil, errors.New(
			"database must not be nil",
		)
	}

	return &DatabaseReadinessChecker{
		db: db,
	}, nil
}

// Check verifies database health and the required schema.
func (c *DatabaseReadinessChecker) Check(
	ctx context.Context,
) error {
	if ctx == nil {
		return errors.New(
			"context must not be nil",
		)
	}

	if c == nil || c.db == nil {
		return errors.New(
			"database readiness checker is not configured",
		)
	}

	if err := databasecheck.CheckHealth(
		ctx,
		c.db,
	); err != nil {
		return fmt.Errorf(
			"database health check: %w",
			err,
		)
	}

	if err := databasecheck.VerifySchema(
		ctx,
		c.db,
	); err != nil {
		return fmt.Errorf(
			"database schema check: %w",
			err,
		)
	}

	return nil
}
