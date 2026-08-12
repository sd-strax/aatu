// Package pgmigrate runs golang-migrate against an embedded migration
// filesystem. Thin wrapper that exists so callers don't have to assemble
// driver + source + migrate.NewWithInstance themselves.
//
// Idempotent: applies pending migrations, returns nil if there are none.
// Migration state is tracked in the standard schema_migrations table inside
// the target database.
package pgmigrate

import (
	"database/sql"
	"errors"
	"fmt"
	"io/fs"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/postgres"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	_ "github.com/lib/pq"
)

// Run applies pending migrations from migrationsFS (rooted at the directory
// containing the .sql files) to the database addressed by dsn.
//
// instanceName is recorded in golang-migrate's internal bookkeeping; use
// distinct names if the same process runs migrations against multiple
// databases (the source is reused otherwise).
//
// Returns nil if there are no pending migrations (migrate.ErrNoChange is
// swallowed — re-running reckon start should be a no-op for already-applied
// schemas).
func Run(dsn string, migrationsFS fs.FS, instanceName string) error {
	return RunWithTable(dsn, migrationsFS, instanceName, "")
}

// RunWithTable is Run with an explicit golang-migrate tracking table. An empty
// table uses the default (schema_migrations); a distinct table lets two
// independently-versioned migration sets share one database without their
// version numbers colliding (e.g. an embedded component's own migrations
// alongside the host's — the memory substrate on reckon_knowledge).
func RunWithTable(dsn string, migrationsFS fs.FS, instanceName, migrationsTable string) error {
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return fmt.Errorf("open postgres: %w", err)
	}
	defer db.Close()

	driver, err := postgres.WithInstance(db, &postgres.Config{MigrationsTable: migrationsTable})
	if err != nil {
		return fmt.Errorf("postgres driver: %w", err)
	}

	// iofs source reads from the embed.FS; "." is the conventional root.
	src, err := iofs.New(migrationsFS, ".")
	if err != nil {
		return fmt.Errorf("iofs source: %w", err)
	}

	m, err := migrate.NewWithInstance(instanceName, src, instanceName, driver)
	if err != nil {
		return fmt.Errorf("migrate instance: %w", err)
	}

	if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return fmt.Errorf("migrate up: %w", err)
	}
	return nil
}
