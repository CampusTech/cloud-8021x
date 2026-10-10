package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/adapters/fleet"
	"github.com/CampusTech/cloud-8021x/internal/adapters/otlp"
	"github.com/CampusTech/cloud-8021x/internal/config"
	"github.com/CampusTech/cloud-8021x/internal/jobs"
	"github.com/CampusTech/cloud-8021x/internal/privileged/host"
	"github.com/CampusTech/cloud-8021x/internal/storage/postgres"
	"github.com/CampusTech/cloud-8021x/internal/telemetry"
	"github.com/jackc/pgx/v5"
)

func protectedWorkRecovery(ctx context.Context, cfg config.Config, o RunOptions) error {
	if o.RecoveryKind != "fleet-terminal" && o.RecoveryKind != "outbox-republish" && o.RecoveryKind != "outbox-receipt" {
		return errors.New("closed recovery kind required")
	}
	if o.RecoveryWork == "" || o.RecoveryGeneration < 1 || len(o.RecoveryExecutions) > 100 {
		return errors.New("exact original work/generation required")
	}
	if o.RecoveryKind != "fleet-terminal" && len(o.RecoveryExecutions) > 0 {
		return errors.New("execution hints are Fleet-only")
	}
	if o.RecoveryKind == "outbox-republish" && !o.AcceptDuplicates && !o.DryRun {
		return errors.New("outbox republication requires --accept-possible-duplicates")
	}
	var e error
	cfg, e = protectedConfiguration(cfg, o)
	if e != nil {
		return e
	}
	if e = cfg.Validate(); e != nil {
		return e
	}
	node, hash, e := transitionBinding(cfg)
	if e != nil {
		return e
	}
	accounts, e := host.ReadAccounts()
	if e != nil {
		return e
	}
	values, e := host.CommittedCredentials(bootCredentialLayout(cfg, accounts))
	if e != nil {
		return e
	}
	repository, e := postgres.NewMigration(ctx, string(values[cfg.Database.MigrationDSN.File]), cfg.Database)
	if e != nil {
		return e
	}
	defer repository.Close()
	backend, e := stateBackend(cfg, values)
	if e != nil {
		return e
	}
	unlock, e := host.AcquireWriterOperation()
	if e != nil {
		return e
	}
	defer unlock()
	if e = repository.RequireWorkerExportReady(ctx, cfg.StateTransition); e != nil {
		return e
	}
	if _, e = host.VerifyDaemonWorkerFence(ctx, cfg.StateTransition, node, hash, backend); e != nil {
		return e
	}
	work, e := repository.LookupWork(ctx, o.RecoveryWork)
	if e != nil {
		return e
	}
	digest := sha256.Sum256(work.Payload)
	payloadHash := hex.EncodeToString(digest[:])
	if work.Generation != o.RecoveryGeneration || (o.RecoveryPayloadSHA != "" && o.RecoveryPayloadSHA != payloadHash) {
		return errors.New("original work generation/payload differs")
	}
	emit := func(outcome string, attempt int64) error {
		if o.Output == nil {
			return nil
		}
		return json.NewEncoder(o.Output).Encode(map[string]any{"dry_run": o.DryRun, "work": o.RecoveryWork, "generation": work.Generation, "payload_sha256": payloadHash, "request": o.RecoveryRequest, "outcome": outcome, "attempt": attempt, "workers_blocked": true, "possible_downstream_duplicates": o.RecoveryKind == "outbox-republish"})
	}
	if o.DryRun {
		return emit(work.State, 0)
	}
	if o.RecoveryPayloadSHA == "" {
		return errors.New("exact original payload digest required")
	}
	if o.RecoveryKind == "outbox-receipt" {
		if o.MaintenanceAttempt != 0 || o.RecoveryRequest != "" {
			return errors.New("receipt lookup does not mutate or reconcile maintenance")
		}
		if e = repository.OriginalOutboxSucceeded(ctx, o.RecoveryWork, o.RecoveryGeneration, payloadHash); e != nil {
			return e
		}
		return emit("original_pg_success_only", 0)
	}
	request := postgres.OperatorRecoveryRequest{AcceptPossibleDuplicates: o.AcceptDuplicates, Transition: cfg.StateTransition, Node: node, ConfigSHA256: hash, RequestID: o.RecoveryRequest, WorkID: o.RecoveryWork, Generation: o.RecoveryGeneration, PayloadSHA256: payloadHash, Mode: o.RecoveryKind}
	requestBytes, _ := json.Marshal(request)
	requestHash := stateDigest(requestBytes)
	if o.MaintenanceAttempt > 0 {
		if e = repository.RecoverOperatorAttempt(ctx, request, o.MaintenanceAttempt, func() ([]byte, error) {
			return host.ProveOperatorAttemptStopped(request.RequestID, requestHash, o.MaintenanceAttempt)
		}); e != nil {
			return e
		}
		result, e := repository.OperatorRecovery(ctx, request)
		if e != nil {
			return e
		}
		return emit(result.Outcome, result.Attempt)
	}
	if existing, e := repository.OperatorRecovery(ctx, request); e == nil {
		if existing.Outcome == "started" {
			return errors.New("original operator attempt retained; use its exact --resume-attempt after helper exit")
		}
		return emit(existing.Outcome, existing.Attempt)
	} else if !errors.Is(e, pgx.ErrNoRows) {
		return e
	}
	var proof fleet.LegacyRecoveryEvidence
	var transport telemetry.Transport
	var record telemetry.BusinessRecord
	if o.RecoveryKind == "fleet-terminal" {
		if cfg.Inventory.Provider != "fleet" || !cfg.Inventory.Enabled {
			return errors.New("configured Fleet provider required")
		}
		client, e := fleet.NewClient(cfg.Inventory.Fleet.BaseURL, string(bytes.TrimSpace(values[cfg.Inventory.Fleet.MaintainerToken.File])), nil, cfg.Inventory.Fleet.Timeout)
		if e != nil {
			return e
		}
		proof, e = client.RecoverCollectionWork(ctx, work.Payload, work.Receipt, o.RecoveryExecutions)
		if e != nil {
			return e
		}
	} else {
		record, e = telemetry.Project(jobs.Claim{ID: o.RecoveryWork, Kind: "outbox", Payload: work.Payload}, nil)
		if e != nil {
			return e
		}
		transport, e = recoveryTransport(cfg, values)
		if e != nil {
			return e
		}
	}
	outcome := ""
	var attempt int64
	e = (postgres.MaintenanceGate{Store: repository}).With(ctx, "work-recovery:"+request.RequestID, func(ctx context.Context) error {
		if _, e = host.VerifyDaemonWorkerFence(ctx, cfg.StateTransition, node, hash, backend); e != nil {
			return e
		}
		attempt, e = repository.OperatorMaintenanceAttempt(ctx, request)
		if e != nil {
			return e
		}
		if e = host.PrepareOperatorAttempt(request.RequestID, requestHash, attempt, postgres.OperatorWorkArchive(work)); e != nil {
			return e
		}
		if _, e = repository.StartOperatorRecovery(ctx, request); e != nil {
			return e
		}
		if request.Mode == "fleet-terminal" {
			outcome = "terminal"
			return repository.FinishFleetRecovery(ctx, request, proof)
		}
		call, cancel := context.WithTimeout(ctx, cfg.Telemetry.Timeout)
		receipt := transport.Send(call, []telemetry.BusinessRecord{record})
		cancel()
		outcome = string(receipt.Outcome)
		raw, _ := json.Marshal(receipt)
		// Cancellation/lost lease leaves durable started work for proof-only recovery;
		// it never grants another call or falsely records a successful handoff.
		finish, stop := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer stop()
		return repository.FinishOperatorRecovery(finish, request, outcome, raw)
	})
	if e != nil {
		return e
	}
	return emit(outcome, attempt)
}
func recoveryTransport(cfg config.Config, values map[string][]byte) (telemetry.Transport, error) {
	options := otlp.Options{Endpoint: cfg.Telemetry.BusinessEndpoint, Timeout: cfg.Telemetry.Timeout}
	if path := cfg.Telemetry.Credential.File; path != "" {
		value, ok := values[path]
		if !ok {
			return nil, errors.New("committed OTLP credential unavailable")
		}
		options.Token = string(bytes.TrimSpace(value))
	}
	if cfg.Telemetry.CAFile != "" {
		ca, e := readInventoryFile(cfg.Telemetry.CAFile, false, 1<<20)
		if e != nil {
			return nil, e
		}
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM(ca) {
			return nil, errors.New("invalid OTLP trust")
		}
		options.TLS = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}
	}
	return otlp.NewHTTP(options)
}
