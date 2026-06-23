package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"containgo.local/containgo/migrations"

	_ "modernc.org/sqlite"
)

const driverName = "sqlite"

// Open creates or opens a SQLite database and applies pending migrations.
func Open(
	ctx context.Context,
	path string,
) (*sql.DB, error) {
	if ctx == nil {
		return nil, errors.New(
			"context must not be nil",
		)
	}

	path = strings.TrimSpace(path)
	if path == "" {
		return nil, errors.New(
			"database path must not be empty",
		)
	}

	if err := ensureParentDirectory(path); err != nil {
		return nil, err
	}

	dsn, err := buildDSN(path)
	if err != nil {
		return nil, err
	}

	db, err := sql.Open(
		driverName,
		dsn,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"open SQLite database: %w",
			err,
		)
	}

	db.SetMaxOpenConns(4)
	db.SetMaxIdleConns(4)

	closeOnError := func(
		openErr error,
	) (*sql.DB, error) {
		if closeErr := db.Close(); closeErr != nil {
			return nil, errors.Join(
				openErr,
				fmt.Errorf(
					"close database: %w",
					closeErr,
				),
			)
		}

		return nil, openErr
	}

	if err = db.PingContext(ctx); err != nil {
		return closeOnError(
			fmt.Errorf(
				"ping SQLite database: %w",
				err,
			),
		)
	}

	var journalMode string

	err = db.QueryRowContext(
		ctx,
		`PRAGMA journal_mode = WAL`,
	).Scan(&journalMode)
	if err != nil {
		return closeOnError(
			fmt.Errorf(
				"enable SQLite WAL mode: %w",
				err,
			),
		)
	}

	if path != ":memory:" &&
		!strings.EqualFold(
			journalMode,
			"wal",
		) {
		return closeOnError(
			fmt.Errorf(
				"enable SQLite WAL mode: database returned %q",
				journalMode,
			),
		)
	}

	if err = migrations.Apply(
		ctx,
		db,
	); err != nil {
		return closeOnError(
			fmt.Errorf(
				"apply database migrations: %w",
				err,
			),
		)
	}

	return db, nil
}

func buildDSN(
	path string,
) (string, error) {
	query := url.Values{}

	query.Add(
		"_pragma",
		"foreign_keys(1)",
	)

	query.Add(
		"_pragma",
		"busy_timeout(5000)",
	)

	query.Set(
		"_time_format",
		"sqlite",
	)

	query.Set(
		"_timezone",
		"UTC",
	)

	query.Set(
		"_txlock",
		"immediate",
	)

	if path == ":memory:" {
		return "file:containgo-memory?" +
			"mode=memory&cache=shared&" +
			query.Encode(), nil
	}

	absolutePath, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf(
			"resolve database path %q: %w",
			path,
			err,
		)
	}

	slashPath := filepath.ToSlash(
		absolutePath,
	)

	if volume := filepath.VolumeName(
		absolutePath,
	); volume != "" {
		slashPath = "/" + slashPath
	}

	databaseURL := url.URL{
		Scheme:   "file",
		Path:     slashPath,
		RawQuery: query.Encode(),
	}

	return databaseURL.String(), nil
}

func ensureParentDirectory(
	path string,
) error {
	if path == ":memory:" {
		return nil
	}

	absolutePath, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf(
			"resolve database path %q: %w",
			path,
			err,
		)
	}

	parentDirectory := filepath.Dir(
		absolutePath,
	)

	if err = os.MkdirAll(
		parentDirectory,
		0o750,
	); err != nil {
		return fmt.Errorf(
			"create database directory %q: %w",
			parentDirectory,
			err,
		)
	}

	return nil
}
