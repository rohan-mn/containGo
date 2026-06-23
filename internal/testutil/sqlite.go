package testutil

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"

	"containgo.local/containgo/internal/database"
)

// OpenSQLite opens a migrated temporary SQLite database for a test.
func OpenSQLite(
	t testing.TB,
) *sql.DB {
	t.Helper()

	databasePath := filepath.Join(
		t.TempDir(),
		"containgo.db",
	)

	db, err := database.Open(
		context.Background(),
		databasePath,
	)
	if err != nil {
		t.Fatalf(
			"open temporary SQLite database: %v",
			err,
		)
	}

	t.Cleanup(func() {
		if closeErr := db.Close(); closeErr != nil {
			t.Errorf(
				"close temporary SQLite database: %v",
				closeErr,
			)
		}
	})

	return db
}
