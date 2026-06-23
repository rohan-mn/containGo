package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"strings"
)

// RequiredTables contains the tables needed by the ContainGo
// persistence layer.
var RequiredTables = []string{
	"workloads",
	"security_events",
	"risk_contributions",
	"incidents",
	"incident_reasons",
	"audit_log",
}

// VerifySchema checks that all required ContainGo tables exist.
func VerifySchema(
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

	rows, err := db.QueryContext(
		ctx,
		`
			SELECT name
			FROM sqlite_master
			WHERE type = 'table'
			  AND name NOT LIKE 'sqlite_%'
		`,
	)
	if err != nil {
		return fmt.Errorf(
			"query SQLite schema: %w",
			err,
		)
	}

	defer func() {
		_ = rows.Close()
	}()

	existingTables := make(
		map[string]struct{},
	)

	for rows.Next() {
		var tableName string

		if err = rows.Scan(
			&tableName,
		); err != nil {
			return fmt.Errorf(
				"scan SQLite table name: %w",
				err,
			)
		}

		normalizedName := strings.ToLower(
			strings.TrimSpace(tableName),
		)

		existingTables[normalizedName] = struct{}{}
	}

	if err = rows.Err(); err != nil {
		return fmt.Errorf(
			"iterate SQLite tables: %w",
			err,
		)
	}

	missingTables := make(
		[]string,
		0,
	)

	for _, requiredTable := range RequiredTables {
		normalizedName := strings.ToLower(
			strings.TrimSpace(requiredTable),
		)

		if _, exists := existingTables[normalizedName]; !exists {
			missingTables = append(
				missingTables,
				requiredTable,
			)
		}
	}

	if len(missingTables) > 0 {
		sort.Strings(missingTables)

		return fmt.Errorf(
			"database schema is incomplete; missing tables: %s",
			strings.Join(
				missingTables,
				", ",
			),
		)
	}

	return nil
}
