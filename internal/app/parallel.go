package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/adapters/freeradius/native"
	"github.com/CampusTech/cloud-8021x/internal/adapters/stepca"
	"github.com/CampusTech/cloud-8021x/internal/adoption"
	"github.com/CampusTech/cloud-8021x/internal/config"
	"github.com/CampusTech/cloud-8021x/internal/privileged/host"
	"github.com/CampusTech/cloud-8021x/internal/storage/postgres"
	"github.com/CampusTech/cloud-8021x/internal/templates/systemd"
)

func protectedParallel(ctx context.Context, op Operation, cfg config.Config, o RunOptions) error {
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
	if !cfg.Parallel() {
		return errors.New("explicit parallel deployment required")
	}
	if o.MaintenanceAttempt < 0 {
		return errors.New("invalid parallel recovery attempt")
	}
	if o.DryRun {
		if o.Output == nil {
			return nil
		}
		return json.NewEncoder(o.Output).Encode(map[string]any{"operation": op, "dry_run": true, "deployment": cfg.Deployment, "production_ready": false})
	}
	if op == OperationParallelActivate || op == OperationParallelDeactivate || op == OperationParallelRollbackProof {
		return activateParallel(ctx, op, cfg, o)
	}
	if !o.Incoming {
		return errors.New("parallel preparation and source capture require the fixed incoming release")
	}
	manifest, err := host.LoadManifest()
	if err != nil {
		return err
	}
	if err = host.VerifyParallelExecutable(manifest.ApplicationSHA256); err != nil {
		return err
	}
	if _, err = host.IncomingFiles(); err != nil {
		return err
	}
	if err = host.VerifyArtifacts(ctx, manifest); err != nil {
		return err
	}
	switch op {
	case OperationParallelSourceKey:
		pin, err := host.ParallelSourceKey()
		if err != nil {
			return err
		}
		if o.Output != nil {
			return json.NewEncoder(o.Output).Encode(map[string]string{"source_public_key": pin})
		}
		return nil
	case OperationParallelCapture:
		raw, err := host.CaptureParallelSource(ctx, cfg, manifest.ApplicationSHA256)
		if err != nil {
			return err
		}
		if o.Output != nil {
			return json.NewEncoder(o.Output).Encode(map[string]string{"source_receipt_sha256": stateDigest(raw), "root_transfer_file": "/var/lib/cloud-8021x-bootstrap/parallel-" + cfg.InstanceID + ".json"})
		}
		return nil
	case OperationParallelResumeSource:
		return host.ResumeParallelSource(ctx, cfg, manifest.ApplicationSHA256)
	case OperationParallelPrepare:
		return prepareParallel(ctx, cfg, o, manifest)
	}
	return errors.New("unknown parallel operation")
}
func prepareParallel(ctx context.Context, cfg config.Config, o RunOptions, manifest host.Manifest) (result error) {
	if err := host.VerifyParallelDestinationKey(cfg); err != nil {
		return err
	}
	if err := host.CheckShippingPlatform(); err != nil {
		return err
	}
	if err := host.InstallParallelPassiveBarrier(ctx); err != nil {
		return err
	}
	incoming, err := host.IncomingFiles()
	if err != nil {
		return err
	}
	database, caPEM, err := host.IncomingDatabase(cfg.Database)
	if err != nil {
		return err
	}
	raw, authorization, err := host.ReadParallelSource(cfg, manifest.ApplicationSHA256)
	if err != nil {
		return err
	}
	if authorization.Native == nil {
		return errors.New("original native CA and webhook identities required")
	}
	cloud, credentials, err := bootstrapCredentials(ctx, cfg)
	if err != nil {
		return err
	}
	if stateDigest(credentials[cfg.Policy.ClassSigningKey.File]) != authorization.ClassSHA256 {
		return errors.New("inherited Class key differs from authenticated source")
	}
	if cfg.Database.TLSMode == "cloudsql-instance-ca" {
		if err = cloud.VerifyInstanceCA(ctx, cfg.Database.CloudSQLInstance, cfg.Database.InstanceCAPEMSHA256); err != nil {
			return err
		}
	}
	repository, err := postgres.NewMigration(ctx, string(credentials[cfg.Database.MigrationDSN.File]), database)
	if err != nil {
		return err
	}
	defer repository.Close()
	roles := postgres.Roles{Runtime: cfg.Bootstrap.RuntimeRole, Native: cfg.Bootstrap.NativeRole}
	if err = repository.Migrate(ctx, roles); err != nil {
		return err
	}
	if err = repository.CheckCAIsolation(ctx, roles); err != nil {
		return err
	}
	if o.MaintenanceAttempt > 0 {
		unlock, e := host.AcquireWriterOperation()
		if e != nil {
			return e
		}
		defer unlock()
		return repository.ResumeParallelPrepare(ctx, o.MaintenanceAttempt, cfg, func(ctx context.Context, reference string) (string, string, error) {
			return host.RecoverParallelPrepare(ctx, cfg, manifest.ApplicationSHA256, reference)
		})
	}
	if receipt, trust, e := host.ParallelInstalledReceipt(cfg, manifest.ApplicationSHA256); e != nil {
		return e
	} else if receipt != "" {
		unlock, e := host.AcquireWriterOperation()
		if e != nil {
			return e
		}
		defer unlock()
		if e = host.InstallParallelPassiveBarrier(ctx); e != nil {
			return e
		}
		return (postgres.MaintenanceGate{Store: repository}).With(ctx, postgres.ParallelPrepareOperation(cfg), func(ctx context.Context) error {
			if trust != authorization.TrustSHA256 {
				return errors.New("final source trust differs from completed preparation")
			}
			if err := repository.ImportParallelAuthorization(ctx, cfg, manifest.ApplicationSHA256, raw); err != nil {
				return err
			}
			return repository.RecordParallelPrepared(ctx, cfg, receipt, trust)
		})
	}
	ecSigner, err := cloud.Signer(ctx, cfg.Bootstrap.ECKMS)
	if err != nil {
		return err
	}
	rsaSigner, err := cloud.Signer(ctx, cfg.Bootstrap.RSAKMS)
	if err != nil {
		return err
	}
	prefix := "projects/" + cfg.Bootstrap.ProjectNumber + "/secrets/"
	ec, err := stepca.Adopt(ctx, cloud, stepca.Definition{Kind: stepca.EC, Name: cfg.Bootstrap.CAName, RootSecret: prefix + "smallstep-ca-cert", IntermediateSecret: prefix + "smallstep-intermediate-cert", DecrypterCertSecret: prefix + "smallstep-scep-decrypter-cert", DecrypterKeySecret: prefix + "smallstep-scep-decrypter-key"}, ecSigner.Public(), time.Now())
	if err != nil {
		return err
	}
	rsa, err := stepca.Adopt(ctx, cloud, stepca.Definition{Kind: stepca.RSA, Name: cfg.Bootstrap.CAName + " RSA", RootSecret: prefix + "smallstep-rsa-root-cert", IntermediateSecret: prefix + "smallstep-rsa-intermediate-cert", DecrypterCertSecret: prefix + "smallstep-rsa-scep-decrypter-cert", DecrypterKeySecret: prefix + "smallstep-rsa-scep-decrypter-key"}, rsaSigner.Public(), time.Now())
	if err != nil {
		return err
	}
	server, err := stepca.AdoptServer(ctx, cloud, ec, cfg.Bootstrap.ServerDNS, prefix+"radius-smallstep-server-cert", prefix+"radius-smallstep-server-key", time.Now())
	if err != nil {
		return err
	}
	original := authorization.Native
	if err = stepca.ValidateAdoptedLoopback(original.WebhookCertificate, original.WebhookKey, time.Now()); err != nil {
		return err
	}
	_, port, err := net.SplitHostPort(cfg.Listeners.Webhook.Address)
	if err != nil {
		return err
	}
	webhookPort, err := strconv.Atoi(port)
	if err != nil {
		return err
	}
	caFiles, err := stepca.Render(stepca.RenderOptions{ECDNS: cfg.Bootstrap.ECDNS, RSADNS: cfg.Bootstrap.RSADNS, ECKey: cfg.Bootstrap.ECKMS, RSAKey: cfg.Bootstrap.RSAKMS, ECDB: string(bytes.TrimSpace(credentials[cfg.Bootstrap.ECDB.File])), RSADB: string(bytes.TrimSpace(credentials[cfg.Bootstrap.RSADB.File])), ACME: cfg.Bootstrap.ACMEProvisioner, SCEP: cfg.Bootstrap.SCEPProvisioner, WebhookPort: webhookPort, Inventory: cfg.Inventory.Fleet.ManagedCertificates, RSAMaterial: rsa})
	if err != nil {
		return err
	}
	for path, originalBytes := range map[string][]byte{"/etc/step-ca/config/ca.json": original.ECConfig, "/etc/step-ca-rsa/config/ca.json": original.RSAConfig} {
		if err = stepca.ValidateAdoptedConfig(originalBytes, caFiles[path]); err != nil {
			return err
		}
		caFiles[path] = originalBytes
	}
	if !bytes.Equal(original.ECTemplate, caFiles["/etc/step-ca/templates/x509/wifi-acme.tpl"]) || !bytes.Equal(original.RSATemplate, caFiles["/etc/step-ca-rsa/templates/x509/wifi-scep.tpl"]) {
		return errors.New("preserved CA templates differ from supported enrollment semantics")
	}
	trust := append(append(append(append([]byte(nil), ec.Intermediate...), ec.Root...), rsa.Intermediate...), rsa.Root...)
	if stateDigest(trust) != authorization.TrustSHA256 {
		return errors.New("adopted CA trust differs from authenticated original source")
	}
	if _, err = native.RenderWithSecretsAndDatabaseCA(cfg, strings.Repeat("0", 32), credentials, caPEM); err != nil {
		return err
	}
	plan, err := host.PreparePackages(ctx, manifest)
	if err != nil {
		return err
	}
	if err = host.CheckInitialListeners(cfg); err != nil {
		return err
	}
	unlock, err := host.AcquireWriterOperation()
	if err != nil {
		return err
	}
	defer unlock()
	gate := postgres.MaintenanceGate{Store: repository}
	common, err := cfg.ParallelManifest()
	if err != nil {
		return err
	}
	return withBootstrapReport(ctx, gate.With, postgres.ParallelPrepareOperation(cfg), o.Output, func(ctx context.Context, outcome *bootstrapOutcome) (result error) {
		if err = host.BeginParallelPrepare(cfg, manifest.ApplicationSHA256); err != nil {
			return err
		}
		if err := repository.PrepareCollectionEpoch(ctx, cfg.Deployment.ID, cfg.StateTransition, common, cfg.Deployment.CollectionEpoch); err != nil {
			return err
		}
		if err := repository.ImportParallelAuthorization(ctx, cfg, manifest.ApplicationSHA256, raw); err != nil {
			return err
		}
		// Persistent barriers precede dpkg; they remain on an interrupted preparation.
		if err := host.InstallParallelPassiveBarrier(ctx); err != nil {
			return err
		}
		backend := &host.RadiusBackend{Companions: true}
		passive := &host.PassiveRadius{Backend: backend}
		transaction, err := host.BeginTransaction(func(reference string) error { return repository.RecordInstallation(ctx, reference) })
		if err != nil {
			return err
		}
		defer func() {
			if result != nil {
				result = errors.Join(result, transaction.Rollback(ctx, passive, false))
			}
		}()
		if err = transaction.CaptureInitialState(ctx, passive, nil); err != nil {
			return err
		}
		if err = transaction.MaskPackages(ctx, backend); err != nil {
			return err
		}
		if err = transaction.InstallPackages(ctx, plan); err != nil {
			return err
		}
		accounts, err := transaction.EnsureAccounts(ctx)
		if err != nil {
			return err
		}
		files, err := credentialFiles(cfg, credentials, accounts)
		if err != nil {
			return err
		}
		files = append(files, incoming...)
		adopted, err := host.AdoptionSnapshotFile(authorization.Policy, accounts)
		if err != nil {
			return err
		}
		files = append(files, adopted...)
		if authorization.FingerprintEnforced {
			files = append(files, host.File{Path: cfg.Paths.DowngradeGuardFile, Data: []byte("fingerprint\n"), Mode: 0644})
		}
		collector, err := host.CollectorFiles(cfg, credentials["/run/cloud-8021x-collector/datadog-api-key"], accounts)
		if err != nil {
			return err
		}
		files = append(files, collector...)
		if err = host.VerifyCollector(manifest); err != nil {
			return err
		}
		if err = host.PrepareCollectorStorage(ctx); err != nil {
			return err
		}
		discovery, err := host.BootstrapDiscoveryFiles(cfg.Network.Discovery.Enabled)
		if err != nil {
			return err
		}
		files = append(files, discovery...)
		for base, material := range map[string]stepca.Material{"/etc/step-ca": ec, "/etc/step-ca-rsa": rsa} {
			caFiles[base+"/certs/root_ca.crt"] = material.Root
			caFiles[base+"/certs/intermediate_ca.crt"] = material.Intermediate
			caFiles[base+"/certs/scep_decrypter.crt"] = material.DecrypterCert
			caFiles[base+"/secrets/scep_decrypter_key"] = material.DecrypterKey
		}
		for path, data := range caFiles {
			files = append(files, host.File{Path: path, Data: data, Mode: 0600})
		}
		for path, data := range map[string][]byte{"/etc/cloud-8021x/client-cas.pem": trust, "/etc/cloud-8021x/radius-server.pem": server.Chain, "/etc/cloud-8021x/ec-decrypter.pem": ec.DecrypterCert, "/etc/cloud-8021x/rsa-decrypter.pem": rsa.DecrypterCert, "/etc/cloud-8021x/ec-intermediate.pem": ec.Intermediate, "/etc/cloud-8021x/rsa-intermediate.pem": rsa.Intermediate, "/etc/cloud-8021x/webhook.crt": original.WebhookCertificate, "/usr/local/share/ca-certificates/acme-webhook.crt": original.WebhookCertificate, "/etc/acme-authz-webhook/server.crt": original.WebhookCertificate} {
			files = append(files, host.File{Path: path, Data: data, Mode: 0644})
		}
		files = append(files, host.File{Path: "/etc/acme-authz-webhook/server.key", Data: original.WebhookKey, Mode: 0600}, host.File{Path: "/run/cloud-8021x/credentials/webhook.key", Data: original.WebhookKey, UID: accounts.RuntimeUID, GID: accounts.RuntimeGID, Mode: 0600})
		units, err := systemd.Render()
		if err != nil {
			return err
		}
		for path, data := range units {
			mode := uint32(0644)
			if path == "/etc/sudoers.d/cloud-8021x" {
				mode = 0440
			}
			files = append(files, host.File{Path: path, Data: data, Mode: mode})
		}
		rules, err := host.MetadataRules(accounts.RuntimeUID)
		if err != nil {
			return err
		}
		files = append(files, host.File{Path: host.MetadataRulesFile, Data: rules, Mode: 0600})
		tree, err := native.RenderWithSecretsAndDatabaseCA(cfg, transaction.Reference(), credentials, caPEM)
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
		if err = transaction.Apply(ctx, passive); err != nil {
			return err
		}
		if err = transaction.UnmaskPackages(ctx, backend); err != nil {
			return err
		}
		if err = host.InstallMetadata(ctx, accounts.RuntimeUID); err != nil {
			return err
		}
		if err = host.EnableInstalledUnits(ctx); err != nil {
			return err
		}
		if err = transaction.CompleteInstalled(); err != nil {
			return err
		}
		if err = repository.RecordParallelPrepared(ctx, cfg, transaction.Reference(), stateDigest(trust)); err != nil {
			return err
		}
		outcome.Operation = "parallel-prepared-passive"
		outcome.Changed = true
		outcome.Installation = transaction.Reference()
		return nil
	})
}

func rejectParallelLegacyOperation(op Operation, cfg config.Config) error {
	if !cfg.Parallel() {
		return nil
	}
	switch op {
	case OperationBootstrap, OperationStateFence, OperationStateMigrate, OperationStateExport:
		return fmt.Errorf("%s is an in-place operation; use the closed parallel workflow", op)
	}
	return nil
}

func activateParallel(ctx context.Context, op Operation, cfg config.Config, o RunOptions) error {
	if err := host.VerifyParallelDestinationKey(cfg); err != nil {
		return err
	}
	if o.Incoming {
		return errors.New("activation uses only the completed installed configuration")
	}
	known, err := host.KnownInstallation()
	if err != nil || !known {
		return errors.New("completed parallel installation required")
	}
	manifest, err := host.LoadManifest()
	if err != nil {
		return err
	}
	if err = host.VerifyParallelExecutable(manifest.ApplicationSHA256); err != nil {
		return err
	}
	accounts, err := host.ReadAccounts()
	if err != nil {
		return err
	}
	credentials, err := host.CommittedCredentials(bootCredentialLayout(cfg, accounts))
	if err != nil {
		return err
	}
	repository, err := postgres.NewMigration(ctx, string(credentials[cfg.Database.MigrationDSN.File]), cfg.Database)
	if err != nil {
		return err
	}
	defer repository.Close()
	// Revoke SQL authority before touching the local process fence. The existing
	// typed worker-fence protocol preserves crash recovery and command provenance.
	if op == OperationParallelDeactivate {
		if err = repository.BlockTransition(ctx, cfg.StateTransition); err != nil {
			return err
		}
		unlock, e := host.AcquireWriterOperation()
		if e != nil {
			return e
		}
		e = host.StopParallel(ctx)
		unlock()
		if e != nil {
			return e
		}
		o.FenceOnly = true
		return protectedStateExport(ctx, cfg, o)
	}
	unlock, err := host.AcquireWriterOperation()
	if err != nil {
		return err
	}
	defer unlock()
	if op == OperationParallelRollbackProof {
		if err = repository.RequireParallelRollbackReady(ctx, cfg); err != nil {
			return err
		}
		backend, e := stateBackend(cfg, credentials)
		if e != nil {
			return e
		}
		node, hash, e := transitionBinding(cfg)
		if e != nil {
			return e
		}
		fence, e := host.VerifyDaemonWorkerFence(ctx, cfg.StateTransition, node, hash, backend)
		if e != nil {
			return e
		}
		path, e := host.WriteParallelRollback(cfg, manifest.ApplicationSHA256, fence)
		if e != nil {
			return e
		}
		if o.Output != nil {
			return json.NewEncoder(o.Output).Encode(map[string]string{"root_transfer_file": path})
		}
		return nil
	}
	var source []byte
	var authorization adoption.Authorization
	if o.MaintenanceAttempt == 0 && repository.WorkersAllowed(ctx, cfg.StateTransition) != nil {
		source, authorization, err = host.ReadParallelSource(cfg, manifest.ApplicationSHA256)
		if err != nil {
			return err
		}
	}
	trust, err := host.ReadClientTrust()
	if err != nil {
		return err
	}
	if len(source) > 0 && (stateDigest(trust) != authorization.TrustSHA256 || stateDigest(credentials[cfg.Policy.ClassSigningKey.File]) != authorization.ClassSHA256) {
		return errors.New("final source CA trust or Class key differs from prepared native identity")
	}
	expected, err := native.ExpectedReadiness(cfg, trust)
	if err != nil {
		return err
	}
	backend := &host.RadiusBackend{ECDNS: cfg.Bootstrap.ECDNS, RSADNS: cfg.Bootstrap.RSADNS, CATrust: trust, Local: cfg.Bootstrap.LocalAddress, Peer: cfg.Bootstrap.PeerAddress, Secret: bytes.TrimSpace(credentials[cfg.Bootstrap.HealthSecret.File]), Expected: expected, Companions: true, CollectorAccounts: &accounts}
	if o.MaintenanceAttempt == 0 && len(source) > 0 {
		if err = repository.RequireParallelPrepared(ctx, cfg); err != nil {
			return err
		}
	}
	gate := postgres.MaintenanceGate{Store: repository}
	active := false
	activate := func(ctx context.Context) error {
		if err = host.BeginParallelActivation(cfg, manifest.ApplicationSHA256); err != nil {
			return err
		}
		// Already active nodes need no import or refresh of historical authorization.
		if repository.WorkersAllowed(ctx, cfg.StateTransition) == nil {
			active = true
			return backend.Healthy(ctx)
		}
		running, err := backend.Running(ctx)
		if err != nil {
			return err
		}
		if running {
			if err = host.StopParallel(ctx); err != nil {
				return err
			}
		}
		if err = repository.ResetParallelReadiness(ctx, cfg); err != nil {
			return err
		}
		if err := repository.ImportParallelAuthorization(ctx, cfg, manifest.ApplicationSHA256, source); err != nil {
			return err
		}
		if err := repository.RequireParallelPrepared(ctx, cfg); err != nil {
			return err
		}
		if err := backend.Validate(ctx); err != nil {
			return err
		}
		running, err = backend.Running(ctx)
		if err != nil {
			return err
		}
		if !running {
			if err = host.PublishParallelAuthorization(ctx, cfg, authorization, accounts); err != nil {
				return err
			}
			if err = host.PublishParallelActivation(cfg); err != nil {
				return err
			}
			if err = backend.Activate(ctx); err != nil {
				return err
			}
		}
		if err = backend.Healthy(ctx); err != nil {
			return err
		}
		if _, e := host.CaptureAuthGeneration(ctx, backend); e != nil {
			generation, e := host.CurrentAuthGeneration()
			if e != nil {
				return e
			}
			if e = host.CompleteAuthGeneration(ctx, backend, generation, generation, nil); e != nil {
				return e
			}
		}
		peerReady := backend.PeerReady(ctx) == nil
		active, err = repository.ReadyParallelNode(ctx, cfg, peerReady)
		return err
	}
	if o.MaintenanceAttempt > 0 {
		if err = host.VerifyParallelActivationRecovery(ctx, cfg, manifest.ApplicationSHA256); err != nil {
			return err
		}
		err = repository.ResumeParallelActivation(ctx, o.MaintenanceAttempt, cfg, func(ctx context.Context) error {
			if repository.WorkersAllowed(ctx, cfg.StateTransition) == nil {
				active = true
				return backend.Healthy(ctx)
			}
			if err = host.StopParallel(ctx); err != nil {
				return err
			}
			return repository.ResetParallelReadiness(ctx, cfg)
		})
	} else {
		err = gate.With(ctx, postgres.ParallelActivateOperation(cfg), activate)
	}
	if err != nil {
		return err
	}
	if active {
		if err = host.StartParallelRenewTimer(ctx); err != nil {
			return err
		}
		if err = host.StartSourceTimer(ctx, cfg.Network.Discovery.Enabled); err != nil {
			return err
		}
	}
	if o.Output != nil {
		return json.NewEncoder(o.Output).Encode(map[string]any{"deployment": cfg.Deployment.ID, "instance": cfg.Deployment.Instance, "workers_active": active, "waiting_for_peer": !active, "endpoint_switch_performed": false})
	}
	return nil
}

func requireParallelRuntimeReceipt(cfg config.Config) error {
	raw, err := readInventoryFile(host.ParallelPublicActivationFile, false, 4096)
	if err != nil {
		return errors.New("parallel runtime remains passive pending protected activation")
	}
	var receipt host.ParallelActivation
	if json.Unmarshal(raw, &receipt) != nil || receipt != host.ParallelActivationBinding(cfg) {
		return errors.New("physical deployment activation receipt differs")
	}
	return nil
}
