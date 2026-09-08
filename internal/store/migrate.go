package store

import (
	"context"
	"database/sql"
	"embed"
	"fmt"

	"github.com/jackc/pgx/v5/stdlib" // registers the "pgx" database/sql driver
	"github.com/pressly/goose/v3"
)

// migrationsFS embeds the SAME .sql files that the shipped docker-compose
// Postgres runs. Running the real migrations here — in tests and at startup —
// rather than a hand-written test schema is what keeps the two from drifting
// (spec §6). The isolation conformance test seeds and queries a database created
// by exactly these statements.
//
//go:embed migrations/*.sql
var migrationsFS embed.FS

// Migrate applies all up migrations to the database at connString. goose needs a
// database/sql handle (it manages its own migration-version table), so we open a
// short-lived one via the pgx stdlib driver purely for migration; the service's
// query path uses pgxpool. Both talk to the same Postgres, so there is no second
// schema and no drift.
func Migrate(ctx context.Context, connString string) error {
	db, err := sql.Open("pgx", connString)
	if err != nil {
		return fmt.Errorf("store: open for migrate: %w", err)
	}
	defer db.Close()

	goose.SetBaseFS(migrationsFS)
	if err := goose.SetDialect("postgres"); err != nil {
		return fmt.Errorf("store: goose dialect: %w", err)
	}
	if err := goose.UpContext(ctx, db, "migrations"); err != nil {
		return fmt.Errorf("store: goose up: %w", err)
	}
	return nil
}

var _ = stdlib.GetDefaultDriver // keep the driver import referenced
