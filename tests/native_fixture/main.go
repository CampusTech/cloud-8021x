// Development-only entry point. Not installed as an application service.
package main

import (
	"context"
	"encoding/json"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/accounting"
	"github.com/CampusTech/cloud-8021x/internal/adapters/freeradius/native"
	"github.com/CampusTech/cloud-8021x/internal/adapters/freeradius/policy"
	"github.com/CampusTech/cloud-8021x/internal/config"
	"github.com/CampusTech/cloud-8021x/internal/domain"
	"github.com/CampusTech/cloud-8021x/internal/events/auth"
	"github.com/CampusTech/cloud-8021x/internal/jobs"
	"github.com/CampusTech/cloud-8021x/internal/storage/postgres"
	"github.com/CampusTech/cloud-8021x/internal/telemetry"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

func main() {
	cmd := &cobra.Command{Use: "native-fixture ACTION CONFIG", Args: cobra.ExactArgs(2), RunE: func(cmd *cobra.Command, args []string) error {
		cfg, e := config.Load(args[1])
		if e != nil {
			return e
		}
		switch args[0] {
		case "project":
			var event accounting.Event
			if err := json.NewDecoder(os.Stdin).Decode(&event); err != nil {
				return err
			}
			payload, err := json.Marshal(event)
			if err != nil {
				return err
			}
			record, err := telemetry.Project(jobs.Claim{ID: "accounting:" + event.ID, Payload: payload}, nil)
			if err != nil {
				return err
			}
			return json.NewEncoder(os.Stdout).Encode(record)
		case "render":
			files, e := native.Render(cfg, "0123456789abcdef")
			if e != nil {
				return e
			}
			for name, data := range files {
				p := filepath.Join(cfg.Backends.RadiusConfigDir, name)
				if e = os.MkdirAll(filepath.Dir(p), 0755); e != nil {
					return e
				}
				if e = os.WriteFile(p, data, 0600); e != nil {
					return e
				}
			}
			return nil
		case "serve":
			s, h, e := policy.FromConfig(cfg, nil)
			if e != nil {
				return e
			}
			go func() {
				for range time.Tick(100 * time.Millisecond) {
					f, e := os.Open(cfg.Paths.InventoryFile)
					if e != nil {
						continue
					}
					snapshot, e := domain.DecodeSnapshot(f)
					_ = f.Close()
					if e == nil {
						_ = s.Snapshots().Set(snapshot)
					}
				}
			}()
			return h.Server(cfg.Listeners.Policy.Address).ListenAndServe()
		case "migrate":
			dsn, e := os.ReadFile(cfg.Database.MigrationDSN.File)
			if e != nil {
				return e
			}
			s, e := postgres.NewMigration(context.Background(), string(dsn), cfg.Database)
			if e != nil {
				return e
			}
			defer s.Close()
			return s.Migrate(context.Background(), postgres.Roles{Runtime: "app_runtime", Native: "app_native"})
		case "process":
			dsn, e := os.ReadFile(cfg.Database.RuntimeDSN.File)
			if e != nil {
				return e
			}
			s, e := postgres.New(context.Background(), string(dsn), cfg.Database)
			if e != nil {
				return e
			}
			defer s.Close()
			key, e := os.ReadFile(cfg.Policy.ClassSigningKey.File)
			if e != nil {
				return e
			}
			for {
				r, e := s.ProcessOne(context.Background(), key, cfg.Policy.ClassMaxAge)
				if e != nil {
					return e
				}
				if !r.Processed {
					return nil
				}
				_ = json.NewEncoder(os.Stdout).Encode(r)
			}
		case "ingest":
			dsn, e := os.ReadFile(cfg.Database.RuntimeDSN.File)
			if e != nil {
				return e
			}
			s, e := postgres.New(context.Background(), string(dsn), cfg.Database)
			if e != nil {
				return e
			}
			defer s.Close()
			producer, e := user.Lookup("freerad")
			if e != nil {
				return e
			}
			group, e := user.LookupGroup("cloud8021x-events")
			if e != nil {
				return e
			}
			uid, _ := strconv.Atoi(producer.Uid)
			gid, _ := strconv.Atoi(group.Gid)
			service, _, e := policy.FromConfig(cfg, nil)
			if e != nil {
				return e
			}
			key, e := os.ReadFile(cfg.Policy.ClassSigningKey.File)
			if e != nil {
				return e
			}
			reader, e := auth.New(auth.Options{Directory: cfg.Paths.AuthLogDir, Host: cfg.Hostname, ProducerUID: uid, EventGID: gid, Store: s, Enrich: auth.InventoryEnricher(key, service.Snapshots(), cfg.Policy.InventoryMaxAge)})
			if e != nil {
				return e
			}
			defer func() { _ = reader.Close() }()
			n, e := reader.Poll(context.Background())
			_ = json.NewEncoder(os.Stdout).Encode(n)
			return e
		}
		return nil
	}}
	if e := cmd.Execute(); e != nil {
		logrus.WithError(e).Fatal("native fixture failed")
	}
}
