package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/adapters/freeradius/native"
	"github.com/CampusTech/cloud-8021x/internal/adapters/stepca"
	"github.com/CampusTech/cloud-8021x/internal/config"
	"github.com/CampusTech/cloud-8021x/internal/privileged/host"
	"github.com/CampusTech/cloud-8021x/internal/storage/postgres"
	"github.com/CampusTech/cloud-8021x/internal/telemetry"
)

type diagnosticObservation struct {
	Components   map[string]string  `json:"components"`
	Measurements map[string]float64 `json:"measurements"`
}

// Observations are bounded read-only probes. Unavailable dependencies never
// acquire invented uptime, freshness or successful-delivery measurements.
func observeInstalled(ctx context.Context, cfg config.Config) diagnosticObservation {
	result := diagnosticObservation{Components: map[string]string{}, Measurements: map[string]float64{}}
	bounded, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	for _, component := range []string{"freeradius", "step-ca", "postgres", "collector"} {
		result.Components[component] = "unavailable"
	}
	secret, err := readInventoryFile(cfg.Bootstrap.HealthSecret.File, true, 4096)
	if err == nil && native.ProbeStatus(bounded, net.JoinHostPort(cfg.Bootstrap.LocalAddress, "18121"), bytes.TrimSpace(secret)) == nil {
		result.Components["freeradius"] = "ready"
	}
	if len(cfg.CA.RootFiles) == 1 {
		trust, err := readInventoryFile(cfg.CA.RootFiles[0], false, 1<<20)
		if err == nil && result.Components["freeradius"] == "ready" {
			expected, e := native.ExpectedReadiness(cfg, trust)
			if e != nil || native.ProbeReadiness(bounded, "http://"+net.JoinHostPort(cfg.Bootstrap.LocalAddress, "18122"), bytes.TrimSpace(secret), expected) != nil {
				result.Components["freeradius"] = "policy-unavailable"
			}
		}
		if err == nil && stepca.ProbeHealth(bounded, "127.0.0.1:8443", cfg.Bootstrap.ECDNS, trust) == nil && stepca.ProbeHealth(bounded, "127.0.0.1:8444", cfg.Bootstrap.RSADNS, trust) == nil {
			result.Components["step-ca"] = "ready"
		}
	}
	// This is explicitly transport reachability, not a collector health/delivery
	// assertion. A successful socket alone does not emit backend.up=1.
	dialer := net.Dialer{Timeout: time.Second}
	connection, err := dialer.DialContext(bounded, "tcp", "127.0.0.1:4317")
	if err == nil {
		_ = connection.Close()
		result.Components["collector"] = "transport-reachable"
		if running, e := host.CollectorRunning(bounded); e == nil && running {
			result.Components["collector"] = "running"
		}
	}
	if spool, e := native.ObserveSpool(cfg.Paths.AccountingSpoolDir, time.Now()); e == nil {
		result.Measurements["spool.files"] = float64(spool.Files)
		result.Measurements["spool.bytes"] = float64(spool.Bytes)
		result.Measurements["spool.oldest_age"] = spool.OldestAge.Seconds()
		result.Measurements["spool.free_bytes"] = float64(spool.AvailableBytes)
	}
	dsn, err := readInventoryFile(cfg.Database.RuntimeDSN.File, true, 64<<10)
	if err == nil {
		store, err := postgres.New(bounded, strings.TrimSpace(string(dsn)), cfg.Database)
		if err == nil {
			observation, err := store.ObserveDelivery(bounded)
			store.Close()
			if err == nil {
				result.Components["postgres"] = "ready"
				for name, value := range map[string]int64{"ledger.sessions": observation.Sessions, "ledger.intake": observation.Intake, "ledger.quarantine": observation.Quarantined, "outbox.depth": observation.Outbox} {
					result.Measurements[name] = float64(value)
				}
				if observation.OutboxOldestAge != nil {
					result.Measurements["outbox.oldest_age"] = *observation.OutboxOldestAge
				}
				if observation.UsageAge != nil {
					result.Measurements["usage.age"] = *observation.UsageAge
				}
			}
		}
	}
	return result
}

func diagnostics(ctx context.Context, op Operation, cfg config.Config, o RunOptions) error {
	if os.Geteuid() == 0 {
		if o.ConfigFile != privilegedConfigFile {
			return errors.New("root diagnostics require fixed protected configuration")
		}
		var err error
		cfg, err = readFixedProtectedConfig(privilegedConfigFile)
		if err != nil {
			return err
		}
	}
	if err := cfg.Validate(); err != nil {
		return err
	}
	output := o.Output
	if output == nil {
		output = io.Discard
	}
	if o.DryRun {
		return json.NewEncoder(output).Encode(map[string]any{"operation": op, "dry_run": true, "observations": []string{"freeradius", "step-ca", "postgres", "collector", "ledger"}})
	}
	observations := observeInstalled(ctx, cfg)
	if o.Debug && o.Logger != nil {
		o.Logger.WithContext(ctx).WithField("operation", string(op)).Debug("bounded diagnostics observed")
	}
	if op == OperationMetricsEmit {
		sdk, err := telemetry.Initialize(ctx, cfg.Telemetry, telemetry.Identity{Version: o.Version, Instance: cfg.InstanceID, Environment: cfg.Environment, Host: cfg.Hostname}, io.Discard)
		if err != nil {
			return err
		}
		for name, state := range observations.Components {
			if state == "ready" || state == "running" {
				sdk.Metrics.ObserveComponent(ctx, "backend.up", name, 1)
			}
		}
		for name, value := range observations.Measurements {
			sdk.Metrics.ObserveCluster(ctx, name, cfg.StateTransition, value)
		}
		if err = sdk.Shutdown(context.WithoutCancel(ctx)); err != nil {
			return err
		}
	}
	if err := json.NewEncoder(output).Encode(observations); err != nil {
		return err
	}
	if op == OperationDoctor {
		if observations.Components["collector"] != "running" {
			return errors.New("installed collector process or transport unavailable")
		}
		for _, name := range []string{"freeradius", "step-ca", "postgres"} {
			if observations.Components[name] != "ready" {
				return errors.New("one or more installed backend observations unavailable")
			}
		}
	}
	return ctx.Err()
}
