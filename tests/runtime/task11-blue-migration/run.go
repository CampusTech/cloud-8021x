package main

import (
	"context"
	"errors"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/config"
	"github.com/CampusTech/cloud-8021x/internal/storage/postgres"
)

func migrationConfig(c config.Database) config.Database {
	c.MaxConnections = 1
	c.MinConnections = 0
	return c
}
func execute(ctx context.Context, p prepared, dry bool) error {
	if dry {
		return nil
	}
	if validateDSN([]byte(p.DSN)) != nil || validateBlueConfig(p.Config, p.Config.Bootstrap.Project, p.Config.Database.InstanceCAPEMSHA256) != nil {
		return errors.New("blue migration inputs not validated")
	}
	// One operation/connection fits inside the finalized blue migration role cap2.
	// The shipping constructor pins TLS, erases DSN fallback/options and applies
	// the original connect/query timeouts. No runtime aggregate pool is opened.
	db := migrationConfig(p.Config.Database)
	ctx, cancel := context.WithTimeout(ctx, min(3*db.QueryTimeout+db.ConnectTimeout, 4*time.Minute))
	defer cancel()
	store, err := postgres.NewMigration(ctx, p.DSN, db)
	if err != nil {
		return errors.New("blue migration store unavailable")
	}
	defer store.Close()
	if err = store.Migrate(ctx, postgres.Roles{Runtime: database + "_runtime", Native: database + "_native"}); err != nil {
		return errors.New("blue schema migration failed; inspect database before retrying uncertain outcome")
	}
	return nil
}
