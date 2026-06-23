package migrations

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// Files contains all versioned SQL migrations compiled into the binary.
//
//go:embed *.sql
var Files embed.FS

// Migration represents one versioned database migration.
type Migration struct {
	Version int64
	Name    string
	SQL     string
}

// Load reads and validates every embedded SQL migration.
func Load() ([]Migration, error) {
	names, err := fs.Glob(Files, "*.sql")
	if err != nil {
		return nil, fmt.Errorf(
			"list embedded migrations: %w",
			err,
		)
	}

	sort.Strings(names)

	loaded := make(
		[]Migration,
		0,
		len(names),
	)

	seenVersions := make(
		map[int64]string,
		len(names),
	)

	for _, name := range names {
		migration, loadErr := loadMigration(name)
		if loadErr != nil {
			return nil, loadErr
		}

		if previousName, exists :=
			seenVersions[migration.Version]; exists {
			return nil, fmt.Errorf(
				"duplicate migration version %d in %q and %q",
				migration.Version,
				previousName,
				name,
			)
		}

		seenVersions[migration.Version] = name
		loaded = append(loaded, migration)
	}

	if len(loaded) == 0 {
		return nil, errors.New(
			"no embedded SQL migrations found",
		)
	}

	sort.Slice(
		loaded,
		func(left, right int) bool {
			return loaded[left].Version <
				loaded[right].Version
		},
	)

	return loaded, nil
}

// Apply executes every migration that has not already been applied.
func Apply(
	ctx context.Context,
	db *sql.DB,
) error {
	if ctx == nil {
		return errors.New(
			"context must not be nil",
		)
	}

	if db == nil {
		return errors.New(
			"database must not be nil",
		)
	}

	_, err := db.ExecContext(
		ctx,
		`
			CREATE TABLE IF NOT EXISTS schema_migrations (
				version INTEGER PRIMARY KEY,
				name TEXT NOT NULL,
				applied_at DATETIME NOT NULL
			)
		`,
	)
	if err != nil {
		return fmt.Errorf(
			"create schema_migrations table: %w",
			err,
		)
	}

	loaded, err := Load()
	if err != nil {
		return err
	}

	for _, migration := range loaded {
		applied, checkErr := isApplied(
			ctx,
			db,
			migration.Version,
		)
		if checkErr != nil {
			return checkErr
		}

		if applied {
			continue
		}

		if applyErr := applyOne(
			ctx,
			db,
			migration,
		); applyErr != nil {
			return applyErr
		}
	}

	return nil
}

func loadMigration(
	name string,
) (Migration, error) {
	base := filepath.Base(name)
	extension := filepath.Ext(base)
	stem := strings.TrimSuffix(
		base,
		extension,
	)

	parts := strings.SplitN(
		stem,
		"_",
		2,
	)

	if extension != ".sql" ||
		len(parts) != 2 ||
		parts[1] == "" {
		return Migration{}, fmt.Errorf(
			"migration filename %q must use NNNN_name.sql form",
			name,
		)
	}

	version, err := strconv.ParseInt(
		parts[0],
		10,
		64,
	)
	if err != nil || version <= 0 {
		return Migration{}, fmt.Errorf(
			"migration filename %q has invalid version",
			name,
		)
	}

	sqlBytes, err := Files.ReadFile(name)
	if err != nil {
		return Migration{}, fmt.Errorf(
			"read migration %q: %w",
			name,
			err,
		)
	}

	sqlText := strings.TrimSpace(
		string(sqlBytes),
	)
	if sqlText == "" {
		return Migration{}, fmt.Errorf(
			"migration %q is empty",
			name,
		)
	}

	return Migration{
		Version: version,
		Name:    parts[1],
		SQL:     sqlText,
	}, nil
}

func isApplied(
	ctx context.Context,
	db *sql.DB,
	version int64,
) (bool, error) {
	var found int

	err := db.QueryRowContext(
		ctx,
		`
			SELECT 1
			FROM schema_migrations
			WHERE version = ?
		`,
		version,
	).Scan(&found)

	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}

	if err != nil {
		return false, fmt.Errorf(
			"check migration version %d: %w",
			version,
			err,
		)
	}

	return true, nil
}

func applyOne(
	ctx context.Context,
	db *sql.DB,
	migration Migration,
) error {
	transaction, err := db.BeginTx(
		ctx,
		nil,
	)
	if err != nil {
		return fmt.Errorf(
			"begin migration %d transaction: %w",
			migration.Version,
			err,
		)
	}

	committed := false

	defer func() {
		if !committed {
			_ = transaction.Rollback()
		}
	}()

	_, err = transaction.ExecContext(
		ctx,
		migration.SQL,
	)
	if err != nil {
		return fmt.Errorf(
			"execute migration %d_%s: %w",
			migration.Version,
			migration.Name,
			err,
		)
	}

	_, err = transaction.ExecContext(
		ctx,
		`
			INSERT INTO schema_migrations(
				version,
				name,
				applied_at
			)
			VALUES (?, ?, CURRENT_TIMESTAMP)
		`,
		migration.Version,
		migration.Name,
	)
	if err != nil {
		return fmt.Errorf(
			"record migration %d_%s: %w",
			migration.Version,
			migration.Name,
			err,
		)
	}

	if err = transaction.Commit(); err != nil {
		return fmt.Errorf(
			"commit migration %d_%s: %w",
			migration.Version,
			migration.Name,
			err,
		)
	}

	committed = true

	return nil
}
