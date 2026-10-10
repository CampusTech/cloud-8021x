package app

import (
	"bytes"
	"context"
	"errors"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/adapters/freeradius/native"
	"github.com/CampusTech/cloud-8021x/internal/adapters/gcp"
	"github.com/CampusTech/cloud-8021x/internal/adapters/stepca"
	"github.com/CampusTech/cloud-8021x/internal/config"
	"github.com/CampusTech/cloud-8021x/internal/events/auth"
	"github.com/CampusTech/cloud-8021x/internal/privileged/host"
	"github.com/CampusTech/cloud-8021x/internal/storage/postgres"
)

func setParallelRenewalAuthCleanup(backend *host.RadiusBackend, hostname, next, rollback string, accounts host.Accounts, store auth.CursorBatch) {
	backend.AuthCleanup = func(ctx context.Context) error {
		_, err := host.PruneClosedAuthGenerations(ctx, backend, hostname, next, rollback, accounts, store)
		return err
	}
}

// Activated green renewal adopts existing CA material forever. It has no CA
// initialization/recovery fallback and cannot run before the worker handoff.
func renewParallel(ctx context.Context, cfg config.Config, o RunOptions) error {
	cfg, err := protectedConfiguration(cfg, o)
	if err != nil {
		return err
	}
	if err = cfg.Validate(); err != nil {
		return err
	}
	if err = cfg.ValidateBootstrap(); err != nil {
		return err
	}
	if o.DryRun {
		return renewalPlan(cfg, o)
	}
	if err = requireParallelRuntimeReceipt(cfg); err != nil {
		return err
	}
	accounts, err := host.ReadAccounts()
	if err != nil {
		return err
	}
	values, err := host.CommittedCredentials(bootCredentialLayout(cfg, accounts))
	if err != nil {
		return err
	}
	repository, err := postgres.NewMigration(ctx, string(values[cfg.Database.MigrationDSN.File]), cfg.Database)
	if err != nil {
		return err
	}
	defer repository.Close()
	if err = repository.WorkersAllowed(ctx, cfg.StateTransition); err != nil {
		return err
	}
	cloud, err := gcp.NewRoot(cfg.Bootstrap.Project, cfg.Bootstrap.ProjectNumber)
	if err != nil {
		return err
	}
	unlock, err := host.AcquireWriterOperation()
	if err != nil {
		return err
	}
	defer unlock()
	gate := postgres.MaintenanceGate{Store: repository}
	return withBootstrapReport(ctx, gate.With, "parallel-renew", o.Output, func(ctx context.Context, outcome *bootstrapOutcome) (result error) {
		if err := repository.WorkersAllowed(ctx, cfg.StateTransition); err != nil {
			return err
		}
		signer, err := cloud.Signer(ctx, cfg.Bootstrap.ECKMS)
		if err != nil {
			return err
		}
		prefix := "projects/" + cfg.Bootstrap.ProjectNumber + "/secrets/"
		ec, err := stepca.Adopt(ctx, cloud, stepca.Definition{Kind: stepca.EC, Name: cfg.Bootstrap.CAName, RootSecret: prefix + "smallstep-ca-cert", IntermediateSecret: prefix + "smallstep-intermediate-cert", DecrypterCertSecret: prefix + "smallstep-scep-decrypter-cert", DecrypterKeySecret: prefix + "smallstep-scep-decrypter-key"}, signer.Public(), time.Now())
		if err != nil {
			return err
		}
		trust, err := host.ReadClientTrust()
		if err != nil {
			return err
		}
		if !bytes.Contains(trust, ec.Root) || !bytes.Contains(trust, ec.Intermediate) {
			return errors.New("adopted CA differs from installed preserved trust")
		}
		expected, err := native.ExpectedReadiness(cfg, trust)
		if err != nil {
			return err
		}
		backend := &host.RadiusBackend{ECDNS: cfg.Bootstrap.ECDNS, RSADNS: cfg.Bootstrap.RSADNS, CATrust: trust, Local: cfg.Bootstrap.LocalAddress, Peer: cfg.Bootstrap.PeerAddress, Secret: bytes.TrimSpace(values[cfg.Bootstrap.HealthSecret.File]), Expected: expected, Companions: true, CollectorAccounts: &accounts}
		if err = host.CheckRestart(ctx, backend); err != nil {
			return err
		}
		rollbackAuth, err := host.CurrentAuthGeneration()
		if err != nil {
			return err
		}
		priorAuth, err := host.CaptureAuthGeneration(ctx, backend)
		if err != nil {
			return err
		}
		current, err := host.ReadNativeServerCache()
		if err != nil {
			return err
		}
		server, err := (&stepca.ServerBackend{LocalCache: current, Store: cloud, Gate: gate, Signer: signer, CA: ec, DNSName: cfg.Bootstrap.ServerDNS, CertificateSecret: prefix + "radius-smallstep-server-cert", KeySecret: prefix + "radius-smallstep-server-key"}).Renew(ctx)
		if err != nil {
			return err
		}
		oldWebhook, err := host.ReadWebhookCache()
		if err != nil {
			return err
		}
		webhook, err := stepca.LoopbackTLS(oldWebhook, time.Now())
		if err != nil {
			return err
		}
		if bytes.Equal(current.Chain, server.Chain) && bytes.Equal(oldWebhook.Certificate, webhook.Certificate) {
			return nil
		}
		transaction, err := host.BeginTransaction(func(ref string) error { return repository.RecordInstallation(ctx, ref) })
		if err != nil {
			return err
		}
		defer func() {
			if result != nil {
				result = errors.Join(result, transaction.Rollback(ctx, backend, false))
			}
		}()
		rollbackBackend := *backend
		if err = transaction.CaptureInitialState(ctx, backend, &rollbackBackend); err != nil {
			return err
		}
		files, err := credentialFiles(cfg, values, accounts)
		if err != nil {
			return err
		}
		collector, err := host.CollectorFiles(cfg, values["/run/cloud-8021x-collector/datadog-api-key"], accounts)
		if err != nil {
			return err
		}
		files = append(files, collector...)
		for path, data := range map[string][]byte{"/etc/cloud-8021x/radius-server.pem": server.Chain, "/etc/cloud-8021x/webhook.crt": webhook.Certificate, "/etc/acme-authz-webhook/server.crt": webhook.Certificate, "/usr/local/share/ca-certificates/acme-webhook.crt": webhook.Certificate} {
			files = append(files, host.File{Path: path, Data: data, Mode: 0644})
		}
		files = append(files, host.File{Path: "/etc/acme-authz-webhook/server.key", Data: webhook.Key, Mode: 0600}, host.File{Path: "/run/cloud-8021x/credentials/webhook.key", Data: webhook.Key, UID: accounts.RuntimeUID, GID: accounts.RuntimeGID, Mode: 0600})
		tree, err := native.RenderWithSecrets(cfg, transaction.Reference(), values)
		if err != nil {
			return err
		}
		tree["certs/server-cert.pem"] = server.Chain
		tree["certs/server-key.pem"] = server.Key
		cached, err := transaction.CredentialCacheFiles(files, tree)
		if err != nil {
			return err
		}
		files = append(files, cached...)
		if err = host.PrepareFileDirectories(files); err != nil {
			return err
		}
		if err = transaction.Prepare(tree, files); err != nil {
			return err
		}
		setParallelRenewalAuthCleanup(backend, cfg.Hostname, transaction.Reference(), rollbackAuth, accounts, repository)
		if err = transaction.Apply(ctx, backend); err != nil {
			return err
		}
		if err = transaction.CompleteInstalled(); err != nil {
			return err
		}
		if err = host.CompleteAuthGeneration(ctx, backend, transaction.Reference(), transaction.Reference(), priorAuth); err != nil {
			return err
		}
		outcome.Changed = true
		outcome.Installation = transaction.Reference()
		return nil
	})
}
