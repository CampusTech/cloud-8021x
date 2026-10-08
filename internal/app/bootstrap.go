package app

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/adapters/freeradius/native"
	"github.com/CampusTech/cloud-8021x/internal/adapters/gcp"
	"github.com/CampusTech/cloud-8021x/internal/adapters/stepca"
	"github.com/CampusTech/cloud-8021x/internal/config"
	"github.com/CampusTech/cloud-8021x/internal/privileged/host"
	"github.com/CampusTech/cloud-8021x/internal/storage/postgres"
	"github.com/CampusTech/cloud-8021x/internal/templates/systemd"
)

func bootstrapPlan(cfg config.Config, o RunOptions, renew bool) error {
	if e := cfg.ValidateBootstrap(); e != nil {
		return e
	}
	steps := []string{"validate-protected-artifact-manifest", "fetch-exact-secret-versions", "verify-cloud-sql-ca", "verify-schema-3-and-ca-role-isolation", "shared-maintenance", "adopt-or-recover-preserved-ca", "validate-server-certificate", "persist-last-known-good", "validate-native-config", "authenticate-peer-readiness", "activate-and-verify"}
	if renew {
		steps = []string{"fetch-exact-secret-versions", "shared-maintenance", "validate-preserved-ca-and-server-cache", "renew-due-fixed-server-and-loopback-webhook-identities", "persist-last-known-good", "validate-native-config", "authenticate-peer-readiness", "activate-and-verify"}
	}
	if o.Output == nil {
		return nil
	}
	return json.NewEncoder(o.Output).Encode(struct {
		DryRun     bool                     `json:"dry_run"`
		Steps      []string                 `json:"steps"`
		References []config.BootstrapSecret `json:"secret_references"`
	}{true, steps, cfg.Bootstrap.Secrets})
}
func protectedConfiguration(cfg config.Config, o RunOptions) (config.Config, error) {
	if os.Geteuid() != 0 {
		if o.DryRun {
			return cfg, nil
		}
		return config.Config{}, errors.New("protected operation requires root")
	}
	if o.ConfigFile != privilegedConfigFile {
		return config.Config{}, errors.New("root operation requires fixed protected configuration")
	}
	if o.Incoming {
		return readFixedProtectedConfig("/var/cache/cloud-8021x/artifacts/config.yaml")
	}
	return readProtectedSourceConfig()
}
func bootstrapCredentials(ctx context.Context, cfg config.Config) (*gcp.Client, map[string][]byte, error) {
	cloud, e := gcp.NewRoot(cfg.Bootstrap.Project, cfg.Bootstrap.ProjectNumber)
	if e != nil {
		return nil, nil, e
	}
	credentials := map[string][]byte{}
	for _, ref := range cfg.Bootstrap.Secrets {
		value, e := cloud.Latest(ctx, ref.Resource)
		if e != nil {
			return nil, nil, errors.New("required protected credential unavailable")
		}
		credentials[ref.File] = value
	}
	return cloud, credentials, nil
}
func credentialLayout(cfg config.Config, a host.Accounts) []host.File {
	files := make([]host.File, 0, len(cfg.Bootstrap.Secrets)+2)
	for _, ref := range cfg.Bootstrap.Secrets {
		uid, gid := 0, 0
		switch ref.Owner {
		case "runtime":
			uid, gid = a.RuntimeUID, a.RuntimeGID
		case "collector":
			uid, gid = a.CollectorUID, a.CollectorGID
		}
		files = append(files, host.File{Path: ref.File, UID: uid, GID: gid, Mode: 0600})
	}
	return files
}
func bootCredentialLayout(cfg config.Config, a host.Accounts) []host.File {
	return append(credentialLayout(cfg, a), host.File{Path: "/run/cloud-8021x/credentials/webhook.key", UID: a.RuntimeUID, GID: a.RuntimeGID, Mode: 0600}, host.File{Path: "/run/cloud-8021x-collector/datadog.env", UID: a.CollectorUID, GID: a.CollectorGID, Mode: 0600})
}
func credentialFiles(cfg config.Config, values map[string][]byte, a host.Accounts) ([]host.File, error) {
	files := credentialLayout(cfg, a)
	for i := range files {
		file := &files[i]
		data, ok := values[file.Path]
		if !ok || len(data) == 0 {
			return nil, errors.New("credential candidate missing")
		}
		file.Data = data
		if file.Path == cfg.Policy.ClassSigningKey.File {
			old, e := host.Snapshot(*file)
			if e != nil {
				return nil, e
			}
			if old.Exists && !bytes.Equal(old.Data, data) {
				return nil, errors.New("shared Class key differs from installed bytes; explicit migration required")
			}
		}
	}
	return files, nil
}
func protectedBootstrap(ctx context.Context, cfg config.Config, o RunOptions, renew bool) error {
	cfg, e := protectedConfiguration(cfg, o)
	if e != nil {
		return e
	}
	if e = cfg.Validate(); e != nil {
		return e
	}
	if e = cfg.ValidateBootstrap(); e != nil {
		return e
	}
	if o.DryRun {
		return bootstrapPlan(cfg, o, renew)
	}
	var manifest host.Manifest
	var packagePlan host.PackagePlan
	var incoming []host.File
	if !renew {
		manifest, e = host.LoadManifest()
		if e != nil {
			return e
		}
		if e = host.VerifyArtifacts(ctx, manifest); e != nil {
			return e
		}
		packagePlan, e = host.PreparePackages(ctx, manifest)
		if e != nil {
			return e
		}
		if o.Incoming {
			incoming, e = host.IncomingFiles()
			if e != nil {
				return e
			}
		}
	}
	var cloud *gcp.Client
	var credentials map[string][]byte
	if renew {
		accounts, err := host.ReadAccounts()
		if err != nil {
			return err
		}
		credentials, e = host.CommittedCredentials(bootCredentialLayout(cfg, accounts))
		if e != nil {
			return e
		}
		cloud, e = gcp.NewRoot(cfg.Bootstrap.Project, cfg.Bootstrap.ProjectNumber)
	} else {
		cloud, credentials, e = bootstrapCredentials(ctx, cfg)
	}
	if e != nil {
		return e
	}
	if cfg.Database.TLSMode == "cloudsql-instance-ca" {
		if e = cloud.VerifyInstanceCA(ctx, cfg.Database.CloudSQLInstance, cfg.Database.InstanceCAPEMSHA256); e != nil {
			return e
		}
	}
	repository, e := postgres.NewMigration(ctx, string(credentials[cfg.Database.MigrationDSN.File]), cfg.Database)
	if e != nil {
		return e
	}
	defer repository.Close()
	roles := postgres.Roles{Runtime: cfg.Bootstrap.RuntimeRole, Native: cfg.Bootstrap.NativeRole}
	if e = repository.Migrate(ctx, roles); e != nil {
		return e
	}
	if e = repository.CheckCAIsolation(ctx, roles); e != nil {
		return e
	}
	gate := postgres.MaintenanceGate{Store: repository}
	operation := "bootstrap"
	if renew {
		operation = "certificates renew"
	}
	return gate.With(ctx, operation, func(ctx context.Context) (result error) {
		ecSigner, e := cloud.Signer(ctx, cfg.Bootstrap.ECKMS)
		if e != nil {
			return e
		}
		rsaSigner, e := cloud.Signer(ctx, cfg.Bootstrap.RSAKMS)
		if e != nil {
			return e
		}
		prefix := "projects/" + cfg.Bootstrap.ProjectNumber + "/secrets/"
		manager := stepca.Manager{Store: cloud, Gate: gate, Journal: postgres.CAJournal{Store: repository}}
		ec, e := manager.Ensure(ctx, stepca.Definition{Kind: stepca.EC, Name: cfg.Bootstrap.CAName, RootSecret: prefix + "smallstep-ca-cert", IntermediateSecret: prefix + "smallstep-intermediate-cert", DecrypterCertSecret: prefix + "smallstep-scep-decrypter-cert", DecrypterKeySecret: prefix + "smallstep-scep-decrypter-key", StagingSecret: strings.Replace(cfg.Bootstrap.ECStagingSecret, "projects/"+cfg.Bootstrap.Project+"/", "projects/"+cfg.Bootstrap.ProjectNumber+"/", 1)}, ecSigner)
		if e != nil {
			return e
		}
		rsa, e := manager.Ensure(ctx, stepca.Definition{Kind: stepca.RSA, Name: cfg.Bootstrap.CAName + " RSA", RootSecret: prefix + "smallstep-rsa-root-cert", IntermediateSecret: prefix + "smallstep-rsa-intermediate-cert", DecrypterCertSecret: prefix + "smallstep-rsa-scep-decrypter-cert", DecrypterKeySecret: prefix + "smallstep-rsa-scep-decrypter-key", StagingSecret: strings.Replace(cfg.Bootstrap.RSAStagingSecret, "projects/"+cfg.Bootstrap.Project+"/", "projects/"+cfg.Bootstrap.ProjectNumber+"/", 1)}, rsaSigner)
		if e != nil {
			return e
		}
		localServer, e := host.ReadNativeServerCache()
		if e != nil {
			return e
		}
		certificate, e := (&stepca.ServerBackend{LocalCache: localServer, Store: cloud, Gate: gate, Signer: ecSigner, CA: ec, DNSName: cfg.Bootstrap.ServerDNS, CertificateSecret: prefix + "radius-smallstep-server-cert", KeySecret: prefix + "radius-smallstep-server-key"}).Renew(ctx)
		if e != nil {
			return e
		}
		trust := append(append(append(append([]byte(nil), ec.Intermediate...), ec.Root...), rsa.Intermediate...), rsa.Root...)
		expected, e := native.ExpectedReadiness(cfg, trust)
		if e != nil {
			return e
		}
		webhook, e := host.ReadWebhookCache()
		if e != nil {
			return e
		}
		webhook, e = stepca.LoopbackTLS(webhook, time.Now())
		if e != nil {
			return e
		}
		_, port, e := net.SplitHostPort(cfg.Listeners.Webhook.Address)
		if e != nil {
			return e
		}
		webhookPort, e := strconv.Atoi(port)
		if e != nil {
			return e
		}
		caFiles, e := stepca.Render(stepca.RenderOptions{ECDNS: cfg.Bootstrap.ECDNS, RSADNS: cfg.Bootstrap.RSADNS, ECKey: cfg.Bootstrap.ECKMS, RSAKey: cfg.Bootstrap.RSAKMS, ECDB: string(bytes.TrimSpace(credentials[cfg.Bootstrap.ECDB.File])), RSADB: string(bytes.TrimSpace(credentials[cfg.Bootstrap.RSADB.File])), ACME: cfg.Bootstrap.ACMEProvisioner, SCEP: cfg.Bootstrap.SCEPProvisioner, WebhookPort: webhookPort, Inventory: cfg.Inventory.Fleet.ManagedCertificates, RSAMaterial: rsa})
		if e != nil {
			return e
		}
		if e = host.CheckLegacyClassKey(credentials[cfg.Policy.ClassSigningKey.File]); e != nil {
			return e
		}
		// Pure credential/profile validation precedes any native stop or package mutation.
		if _, e = native.RenderWithSecrets(cfg, strings.Repeat("0", 32), credentials); e != nil {
			return e
		}
		if _, e = host.CollectorEnvironment(credentials["/run/cloud-8021x-collector/datadog-api-key"], host.Accounts{}); e != nil {
			return e
		}
		backend := &host.RadiusBackend{ECDNS: cfg.Bootstrap.ECDNS, RSADNS: cfg.Bootstrap.RSADNS, CATrust: trust, Local: cfg.Bootstrap.LocalAddress, Peer: cfg.Bootstrap.PeerAddress, Secret: bytes.TrimSpace(credentials[cfg.Bootstrap.HealthSecret.File]), Expected: expected, Companions: true}
		if e = host.CheckRestart(ctx, backend); e != nil {
			return e
		}
		known, e := host.KnownInstallation()
		if e != nil {
			return e
		}
		var previous *host.RadiusBackend
		if known {
			oldConfig, err := readFixedProtectedConfig(privilegedConfigFile)
			if err != nil {
				return err
			}
			priorAccounts, err := host.ReadAccounts()
			if err != nil {
				return err
			}
			priorValues, err := host.CommittedCredentials(bootCredentialLayout(oldConfig, priorAccounts))
			if err != nil {
				return err
			}
			if !bytes.Equal(priorValues[oldConfig.Policy.ClassSigningKey.File], credentials[cfg.Policy.ClassSigningKey.File]) {
				return errors.New("shared Class key differs from completed installation; explicit migration required")
			}
			oldTrust, err := host.ReadClientTrust()
			if err != nil {
				return err
			}
			oldSecret, err := readInventoryFile(oldConfig.Bootstrap.HealthSecret.File, true, 4096)
			if err != nil {
				return err
			}
			oldExpected, err := native.ExpectedReadiness(oldConfig, oldTrust)
			if err != nil {
				return err
			}
			previous = &host.RadiusBackend{Local: oldConfig.Bootstrap.LocalAddress, Peer: oldConfig.Bootstrap.PeerAddress, Secret: bytes.TrimSpace(oldSecret), Expected: oldExpected, Companions: true, ECDNS: oldConfig.Bootstrap.ECDNS, RSADNS: oldConfig.Bootstrap.RSADNS, CATrust: oldTrust}
		} else if e = host.CheckInitialListeners(cfg); e != nil {
			return e
		}
		var transaction *host.Transaction
		begin := func() error {
			var err error
			transaction, err = host.BeginTransaction(func(reference string) error { return repository.RecordInstallation(ctx, reference) })
			if err != nil {
				return err
			}
			var prior host.Activation
			if previous != nil {
				prior = previous
			}
			return transaction.CaptureInitialState(ctx, backend, prior)
		}
		if !renew {
			if e = begin(); e != nil {
				return e
			}
		}
		defer func() {
			if result != nil && transaction != nil {
				result = errors.Join(result, transaction.Rollback(ctx, backend, false))
			}
		}()
		var accounts host.Accounts
		if !renew {
			if packagePlan.Changed {
				if e = transaction.MaskPackages(ctx, backend); e != nil {
					return e
				}
			}
			if e = transaction.InstallPackages(ctx, packagePlan); e != nil {
				return e
			}
			accounts, e = transaction.EnsureAccounts(ctx)
		} else {
			accounts, e = host.ReadAccounts()
		}
		if e != nil {
			return e
		}
		backend.CollectorAccounts = &accounts
		if previous != nil {
			previous.CollectorAccounts = &accounts
		}
		files, e := credentialFiles(cfg, credentials, accounts)
		if e != nil {
			return e
		}
		legacyClassFiles, err := host.AdoptLegacyClassKey(credentials[cfg.Policy.ClassSigningKey.File], accounts)
		if err != nil {
			return err
		}
		files = append(files, legacyClassFiles...)
		collectorFiles, err := host.CollectorFiles(cfg, credentials["/run/cloud-8021x-collector/datadog-api-key"], accounts)
		if err != nil {
			return err
		}
		files = append(files, collectorFiles...)
		if cfg.Network.Discovery.Enabled {
			include := host.File{Path: "/etc/cloud-8021x/sources/clients.conf", Data: []byte("# No source candidates have been applied.\n"), Mode: 0600}
			old, err := host.Snapshot(include)
			if err != nil {
				return err
			}
			if !old.Exists {
				files = append(files, include)
			}
		}
		if !renew {
			if e = host.VerifyCollector(manifest); e != nil {
				return e
			}
			if e = host.PrepareCollectorStorage(ctx); e != nil {
				return e
			}
		}
		if o.Incoming {
			files = append(files, incoming...)
		}
		if renew {
			old, e := host.Snapshot(host.File{Path: cfg.CA.ServerCertFile, UID: accounts.NativeUID})
			if e != nil {
				return e
			}
			oldWebhook, e := host.Snapshot(host.File{Path: "/etc/cloud-8021x/webhook.crt"})
			if e != nil {
				return e
			}
			if old.Exists && oldWebhook.Exists && bytes.Equal(old.Data, certificate.Chain) && bytes.Equal(oldWebhook.Data, webhook.Certificate) {
				if o.Output != nil {
					return json.NewEncoder(o.Output).Encode(map[string]any{"operation": "certificates renew", "changed": false})
				}
				return nil
			}
		}
		if transaction == nil {
			if e = begin(); e != nil {
				return e
			}
		}
		for base, material := range map[string]stepca.Material{"/etc/step-ca": ec, "/etc/step-ca-rsa": rsa} {
			caFiles[base+"/certs/root_ca.crt"] = material.Root
			caFiles[base+"/certs/intermediate_ca.crt"] = material.Intermediate
			caFiles[base+"/certs/scep_decrypter.crt"] = material.DecrypterCert
			caFiles[base+"/secrets/scep_decrypter_key"] = material.DecrypterKey
		}
		for path, data := range caFiles {
			files = append(files, host.File{Path: path, Data: data, Mode: 0600})
		}
		for path, data := range map[string][]byte{"/etc/cloud-8021x/client-cas.pem": trust, "/etc/cloud-8021x/ec-intermediate.pem": ec.Intermediate, "/etc/cloud-8021x/rsa-intermediate.pem": rsa.Intermediate, "/etc/cloud-8021x/webhook.crt": webhook.Certificate, "/usr/local/share/ca-certificates/acme-webhook.crt": webhook.Certificate} {
			files = append(files, host.File{Path: path, Data: data, Mode: 0644})
		}
		files = append(files, host.File{Path: "/etc/acme-authz-webhook/server.key", Data: webhook.Key, Mode: 0600}, host.File{Path: "/etc/acme-authz-webhook/server.crt", Data: webhook.Certificate, Mode: 0644}, host.File{Path: "/run/cloud-8021x/credentials/webhook.key", Data: webhook.Key, UID: accounts.RuntimeUID, GID: accounts.RuntimeGID, Mode: 0600})
		units, e := systemd.Render()
		if e != nil {
			return e
		}
		for path, data := range units {
			mode := uint32(0644)
			if path == "/etc/sudoers.d/cloud-8021x" {
				mode = 0440
			}
			files = append(files, host.File{Path: path, Data: data, Mode: mode})
		}
		rules, e := host.MetadataRules(accounts.RuntimeUID)
		if e != nil {
			return e
		}
		files = append(files, host.File{Path: host.MetadataRulesFile, Data: rules, Mode: 0600})
		sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
		var generation [16]byte
		if _, e = rand.Read(generation[:]); e != nil {
			return e
		}
		tree, e := native.RenderWithSecrets(cfg, hex.EncodeToString(generation[:]), credentials)
		if e != nil {
			return e
		}
		tree["certs/server-cert.pem"] = certificate.Chain
		tree["certs/server-key.pem"] = certificate.Key
		cached, err := transaction.CredentialCacheFiles(files, tree)
		if err != nil {
			return err
		}
		files = append(files, cached...)
		if e = host.PrepareFileDirectories(files); e != nil {
			return e
		}
		if e = transaction.Prepare(tree, files); e != nil {
			return e
		}
		if e = transaction.UnmaskPackages(ctx, backend); e != nil {
			return e
		}
		if e = transaction.Apply(ctx, backend); e != nil {
			return e
		}
		if e = host.InstallMetadata(ctx, accounts.RuntimeUID); e != nil {
			return e
		}
		if e = host.EnableInstalledUnits(ctx); e != nil {
			return e
		}
		if e = transaction.CompleteInstalled(); e != nil {
			return e
		}
		if o.Output != nil {
			return json.NewEncoder(o.Output).Encode(map[string]any{"operation": operation, "changed": true, "installation": transaction.Reference()})
		}
		return nil
	})
}
func refreshRootCredentials(ctx context.Context, cfg config.Config, o RunOptions) error {
	cfg, e := protectedConfiguration(cfg, o)
	if e != nil {
		return e
	}
	if e = cfg.ValidateBootstrap(); e != nil {
		return e
	}
	if o.DryRun {
		return bootstrapPlan(cfg, o, false)
	}
	accounts, e := host.ReadAccounts()
	if e != nil {
		return e
	}
	if e = host.PrepareDirectories(accounts); e != nil {
		return e
	}
	if e = host.RestoreBootCredentials(bootCredentialLayout(cfg, accounts)); e != nil {
		return e
	}
	return host.InstallMetadata(ctx, accounts.RuntimeUID)
}
