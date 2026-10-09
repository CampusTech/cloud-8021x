package app

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/user"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/accounting/binding"
	"github.com/CampusTech/cloud-8021x/internal/adapters/freeradius/native"
	radiuspolicy "github.com/CampusTech/cloud-8021x/internal/adapters/freeradius/policy"
	"github.com/CampusTech/cloud-8021x/internal/adapters/network/signaling"
	"github.com/CampusTech/cloud-8021x/internal/adapters/otlp"
	"github.com/CampusTech/cloud-8021x/internal/config"
	"github.com/CampusTech/cloud-8021x/internal/domain"
	"github.com/CampusTech/cloud-8021x/internal/events/auth"
	networkjob "github.com/CampusTech/cloud-8021x/internal/jobs/network"
	"github.com/CampusTech/cloud-8021x/internal/network"
	"github.com/CampusTech/cloud-8021x/internal/storage/postgres"
	"github.com/CampusTech/cloud-8021x/internal/telemetry"
	"github.com/CampusTech/cloud-8021x/internal/webhook/broker"
	webhook "github.com/CampusTech/cloud-8021x/internal/webhook/server"
)

func serveDaemon(ctx context.Context, cfg config.Config, o RunOptions) error {
	if err := cfg.Validate(); err != nil {
		return err
	}
	if o.DryRun {
		if o.Output == nil {
			return nil
		}
		return json.NewEncoder(o.Output).Encode(map[string]any{"dry_run": true, "operation": "serve", "listeners": cfg.Listeners, "accounting_workers": cfg.Schedules.AccountingWorkers, "export_workers": cfg.Schedules.ExportWorkers})
	}
	if cfg.Parallel() {
		if err := requireParallelRuntimeReceipt(cfg); err != nil {
			return err
		}
	}
	account, err := user.Lookup(cfg.RuntimeUser)
	if err != nil {
		return errors.New("dedicated runtime account unavailable")
	}
	uid, err := strconv.Atoi(account.Uid)
	if err != nil || uid == 0 || os.Geteuid() != uid {
		return errors.New("serve requires the dedicated unprivileged runtime account")
	}
	daemon, closeDaemon, err := buildDaemon(ctx, cfg, o)
	if err != nil {
		return err
	}
	defer closeDaemon()
	return daemon.Run(ctx)
}

// Construction uses local credentials/snapshots only. Pool construction does not
// connect; an unavailable shared ledger is a background dependency failure.
func buildDaemon(ctx context.Context, cfg config.Config, o RunOptions) (lifecycle, func(), error) {
	l := lifecycle{Notify: systemdNotify, StopTimeout: cfg.Telemetry.ShutdownTimeout}
	cleanups := []func(){}
	closeAll := func() {
		for i := len(cleanups) - 1; i >= 0; i-- {
			cleanups[i]()
		}
	}
	fail := func(err error) (lifecycle, func(), error) { closeAll(); return lifecycle{}, nil, err }
	metadata := new(network.Store)
	if err := loadLegacyDisplay(cfg, metadata); err != nil {
		return fail(err)
	}
	sites, err := NetworkServiceFromConfig(cfg, metadata, false, nil)
	if err != nil {
		return fail(err)
	}
	entries := []signaling.Registration{}
	seen := map[string]bool{}
	for _, p := range cfg.Network.Providers {
		for _, r := range sites.Registry.Entries {
			if r.ID == p.ID && r.Signaler != nil && !seen[p.Kind] {
				entries = append(entries, signaling.Registration{Profile: signaling.NumericProfile(p.Kind + "-numeric"), Signaler: r.Signaler})
				seen[p.Kind] = true
			}
		}
	}
	registry, err := signaling.NewRegistry(entries)
	if err != nil {
		return fail(err)
	}
	local, handler, err := radiuspolicy.FromConfig(cfg, registry)
	if err != nil {
		return fail(err)
	}
	key, err := binding.ReadKey(cfg.Policy.ClassSigningKey.File)
	if err != nil {
		return fail(err)
	}
	dsn, err := readInventoryFile(cfg.Database.RuntimeDSN.File, true, 64<<10)
	if err != nil {
		return fail(err)
	}
	// Distinct pools prevent telemetry/worker pressure exhausting certificate jobs.
	pool := func(class config.RuntimePool) (*postgres.Store, error) {
		s, e := postgres.NewRuntime(ctx, strings.TrimSpace(string(dsn)), cfg.Database, class)
		if e == nil {
			cleanups = append(cleanups, s.Close)
			s = s.ForTransition(cfg.StateTransition)
		}
		return s, e
	}
	accountingStore, err := pool(config.PoolAccounting)
	if err != nil {
		return fail(err)
	}
	exportStore, err := pool(config.PoolExport)
	if err != nil {
		return fail(err)
	}
	authStore, err := pool(config.PoolAuth)
	if err != nil {
		return fail(err)
	}
	localWriter := io.Writer(os.Stderr)
	if o.Logger != nil {
		localWriter = o.Logger.Out
	}
	telemetryInstance := cfg.InstanceID
	if cfg.Parallel() {
		telemetryInstance = cfg.Deployment.Instance
	}
	sdk, err := telemetry.Initialize(ctx, cfg.Telemetry, telemetry.Identity{Version: o.Version, Instance: telemetryInstance, Environment: cfg.Environment, Host: cfg.Hostname}, localWriter)
	if err != nil {
		return fail(err)
	}
	cleanups = append(cleanups, func() {
		bounded, cancel := context.WithTimeout(context.Background(), cfg.Telemetry.ShutdownTimeout)
		defer cancel()
		_ = sdk.Shutdown(bounded)
	})
	l.Flush = sdk.Shutdown
	l.Logger = sdk.Logger
	add := func(name string, interval, timeout time.Duration, fn func(context.Context) error) {
		l.Jobs = append(l.Jobs, scheduledJob{Name: name, Interval: interval, Timeout: timeout, Run: func(ctx context.Context) error {
			return sdk.Job(ctx, name, nil, func(ctx context.Context) error {
				if name != "metrics" && name != "local-sources" {
					if err := accountingStore.WorkersAllowed(ctx, cfg.StateTransition); err != nil {
						return err
					}
				}
				return fn(ctx)
			})
		}})
	}
	add("local-sources", time.Second, 2*time.Second, func(context.Context) error { return local.RefreshSources() })
	if cfg.Inventory.Enabled {
		inventory, cleanup, err := InventoryServiceFromConfig(ctx, cfg, local.Snapshots(), false, nil)
		if err != nil {
			return fail(err)
		}
		cleanups = append(cleanups, cleanup)
		inventory.Logger = sdk.Logger
		add("inventory", cfg.Schedules.Inventory, 2*time.Minute, func(ctx context.Context) error { return inventory.Sync(ctx, false) })
	}
	// Restore optional display cache at original observation times before refresh.
	if data, e := network.ReadPrivate(cfg.Paths.MetadataFile, os.Geteuid()); e == nil {
		var document networkjob.Document
		if domain.DecodeJSONStrict(data, &document) == nil && document.Key == sites.Key {
			if e = metadata.Replace(document.Providers); e != nil {
				return fail(e)
			}
		}
	}
	if len(cfg.Network.Providers) > 0 {
		add("network", cfg.Schedules.Sites, time.Minute, func(ctx context.Context) error { return sites.Sync(ctx, false) })
	}
	if cfg.Network.Discovery.Enabled {
		discovery, e := SourceDiscoveryFromConfig(cfg, nil)
		if e != nil {
			return fail(e)
		}
		add("sources", cfg.Schedules.Sources, time.Minute, func(ctx context.Context) error {
			_, e := networkjob.Discover(ctx, discovery, cfg.Network.Discovery.CandidateFile, false)
			return e
		})
	}
	for range cfg.Schedules.AccountingWorkers {
		add("accounting", 250*time.Millisecond, 30*time.Second, func(ctx context.Context) error {
			for range 128 {
				result, e := accountingStore.ProcessOne(ctx, key, cfg.Policy.ClassMaxAge)
				if e != nil {
					return e
				}
				if !result.Processed {
					return nil
				}
			}
			return nil
		})
	}
	producer, e := user.Lookup("freerad")
	if e != nil {
		return fail(errors.New("native event producer account unavailable"))
	}
	producerUID, e := strconv.Atoi(producer.Uid)
	if e != nil {
		return fail(e)
	}
	group, e := user.LookupGroup("cloud8021x-events")
	if e != nil {
		return fail(errors.New("native event group unavailable"))
	}
	eventGID, e := strconv.Atoi(group.Gid)
	if e != nil {
		return fail(e)
	}
	reader, e := auth.New(auth.Options{Directory: cfg.Paths.AuthLogDir, Host: cfg.Hostname, ProducerUID: producerUID, EventGID: eventGID, Store: authStore, Capacity: func(n, level int) {
		sdk.Metrics.Observe(ctx, "auth.files", float64(n))
		sdk.Metrics.Observe(ctx, "auth.capacity", float64(level))
	}, Enrich: auth.WithCertificateExpiry(auth.Enricher(cfg, key, local.Snapshots(), metadata), clientCertificateIssuers())})
	if e != nil {
		return fail(e)
	}
	cleanups = append(cleanups, func() { _ = reader.Close() })
	add("accounting", time.Second, 30*time.Second, func(ctx context.Context) error { _, e := reader.Poll(ctx); return e })
	transportOptions := otlp.Options{Endpoint: cfg.Telemetry.BusinessEndpoint, Timeout: cfg.Telemetry.Timeout}
	if cfg.Telemetry.Credential.File != "" {
		token, e := readInventoryFile(cfg.Telemetry.Credential.File, true, 4096)
		if e != nil {
			return fail(e)
		}
		transportOptions.Token = string(bytes.TrimSpace(token))
	}
	if cfg.Telemetry.CAFile != "" {
		ca, e := readInventoryFile(cfg.Telemetry.CAFile, false, 1<<20)
		if e != nil {
			return fail(e)
		}
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM(ca) {
			return fail(errors.New("invalid OTLP trust"))
		}
		transportOptions.TLS = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}
	}
	transport, err := otlp.NewHTTP(transportOptions)
	if err != nil {
		return fail(err)
	}
	for i := range cfg.Schedules.ExportWorkers {
		outbox := telemetry.Outbox{Store: exportStore, Transport: transport, Display: telemetry.NewDisplay(cfg, local.Snapshots(), metadata), Owner: fmt.Sprintf("%s-outbox-%d", cfg.InstanceID, i), Timeout: cfg.Telemetry.Timeout}
		add("outbox", 250*time.Millisecond, 30*time.Second, func(ctx context.Context) error {
			for range 32 {
				did, e := outbox.One(ctx)
				if e != nil {
					return e
				}
				if !did {
					return nil
				}
			}
			return nil
		})
	}
	l.Servers = append(l.Servers, handler.Server(cfg.Listeners.Policy.Address))
	l.Servers[0].Handler = sdk.Handler("policy", handler)
	readiness, err := localReadiness(cfg, local.Snapshots())
	if err != nil {
		return fail(err)
	}

	secret, err := readInventoryFile(cfg.Bootstrap.HealthSecret.File, true, 4096)
	if err != nil {
		return fail(err)
	}
	peers := []string{cfg.Bootstrap.LocalAddress, cfg.Bootstrap.PeerAddress, "127.0.0.1"}
	l.Servers = append(l.Servers, boundedServer(net.JoinHostPort(cfg.Bootstrap.LocalAddress, "18122"), native.ReadinessHandler(bytes.TrimSpace(secret), peers, readiness)))
	policyToken, err := readInventoryFile(cfg.Listeners.Policy.Token.File, true, 4096)
	if err != nil {
		return fail(err)
	}
	l.Ready = func(ctx context.Context) error {
		expected, e := readiness(ctx)
		if e != nil {
			return e
		}
		if e = probePolicyHandler(ctx, cfg.Listeners.Policy.Address, bytes.TrimSpace(policyToken)); e != nil {
			return e
		}
		return native.ProbeReadiness(ctx, "http://"+net.JoinHostPort(cfg.Bootstrap.LocalAddress, "18122"), bytes.TrimSpace(secret), expected)
	}

	if err = appendWebhookServers(&l, cfg, local.Snapshots(), sdk); err != nil {
		return fail(err)
	}
	var observationsMu sync.RWMutex
	observations := diagnosticObservation{Components: map[string]string{}, Measurements: map[string]float64{}}
	add("metrics", cfg.Schedules.Metrics, 15*time.Second, func(ctx context.Context) error {
		next := observeInstalled(ctx, cfg)
		emitObservations(ctx, sdk.Metrics, cfg, next)
		observationsMu.Lock()
		observations = next
		observationsMu.Unlock()
		return nil
	})
	if cfg.Listeners.HealthAddress != "" {
		mux := http.NewServeMux()
		mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
		mux.HandleFunc("GET /ready", func(w http.ResponseWriter, r *http.Request) {
			if _, e := readiness(r.Context()); e != nil {
				http.Error(w, "unready", http.StatusServiceUnavailable)
				return
			}
			w.WriteHeader(http.StatusOK)
		})
		l.Servers = append(l.Servers, boundedServer(cfg.Listeners.HealthAddress, mux))
	}
	if cfg.Listeners.MetricsAddress != "" {
		mux := http.NewServeMux()
		mux.HandleFunc("GET /metrics", func(w http.ResponseWriter, _ *http.Request) {
			observationsMu.RLock()
			defer observationsMu.RUnlock()
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(observations)
		})
		l.Servers = append(l.Servers, boundedServer(cfg.Listeners.MetricsAddress, mux))
	}
	return l, closeAll, nil
}

func boundedServer(address string, handler http.Handler) *http.Server {
	return &http.Server{Addr: address, Handler: handler, ReadHeaderTimeout: 2 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10}
}

// No private key or API is read here. Public installed certificate/trust files are
// re-observed on readiness requests so a later renewal is reflected immediately.
func localReadiness(cfg config.Config, snapshots *domain.SnapshotStore) (func(context.Context) (native.Readiness, error), error) {
	if cfg.Bootstrap.LocalAddress == "" || cfg.Bootstrap.PeerAddress == "" || cfg.Bootstrap.ServerDNS == "" {
		return nil, errors.New("private readiness requires configured peer and server identities")
	}
	return func(ctx context.Context) (native.Readiness, error) {
		if err := ctx.Err(); err != nil {
			return native.Readiness{}, err
		}
		trust, err := readInventoryFile("/etc/cloud-8021x/client-cas.pem", false, 1<<20)
		if err != nil {
			return native.Readiness{}, err
		}
		state, err := native.ExpectedReadiness(cfg, trust)
		if err != nil {
			return state, err
		}
		if !domain.Fresh(snapshots.View().Updated(), time.Now(), cfg.Policy.InventoryMaxAge) {
			return state, errors.New("policy inventory stale")
		}
		data, err := readInventoryFile("/etc/cloud-8021x/radius-server.pem", false, 1<<20)
		if err != nil {
			return state, err
		}
		block, rest := pem.Decode(data)
		if block == nil {
			return state, errors.New("server certificate unavailable")
		}
		leaf, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return state, errors.New("server certificate invalid")
		}
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM(trust) {
			return state, errors.New("client trust invalid")
		}
		intermediates := x509.NewCertPool()
		intermediates.AppendCertsFromPEM(rest)
		if _, err = leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, DNSName: cfg.Bootstrap.ServerDNS, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil || leaf.IsCA {
			return state, errors.New("server certificate not ready")
		}
		state.Ready = true
		return state, nil
	}, nil
}

func appendWebhookServers(l *lifecycle, cfg config.Config, snapshots *domain.SnapshotStore, sdk *telemetry.SDK) error {
	w := cfg.Listeners.Webhook
	loadPair := func(cert, key string) (tls.Certificate, error) {
		data, e := readInventoryFile(cert, false, 1<<20)
		if e != nil {
			return tls.Certificate{}, e
		}
		private, e := readInventoryFile(key, true, 64<<10)
		if e != nil {
			return tls.Certificate{}, e
		}
		pair, e := tls.X509KeyPair(data, private)
		if e != nil {
			return tls.Certificate{}, errors.New("listener TLS identity invalid")
		}
		return pair, nil
	}
	if w.Enabled {
		var trust []byte
		for _, path := range w.ClientCAFiles {
			data, e := readInventoryFile(path, false, 1<<20)
			if e != nil {
				return e
			}
			trust = append(trust, data...)
		}
		tlsConfig, e := webhook.ClientTLSConfig(trust, w.ClientDNSNames)
		if e != nil {
			return e
		}
		pair, e := loadPair(w.CertFile, w.KeyFile.File)
		if e != nil {
			return e
		}
		tlsConfig.Certificates = []tls.Certificate{pair}
		signing := ""
		if cfg.Inventory.Fleet.ChallengeSigningKey.File != "" {
			data, e := readInventoryFile(cfg.Inventory.Fleet.ChallengeSigningKey.File, true, 4096)
			if e != nil {
				return e
			}
			signing = string(bytes.TrimSpace(data))
		}
		decider := webhook.DeciderFunc(func(value string) bool {
			view := snapshots.View()
			if !domain.Fresh(view.Updated(), time.Now(), cfg.Policy.InventoryMaxAge) {
				return false
			}
			device := view.ByIdentity(domain.NormalizeIdentity(value))
			return device != nil && device.Enrolled
		})
		h := webhook.NewMutualTLS(signing, decider)
		if cfg.Inventory.Fleet.ManagedCertificates {
			h = webhook.NewMutualTLSInventory(signing, cfg.Inventory.Fleet.SCEPProvisioner, decider)
		}
		s := boundedServer(w.Address, sdk.Handler("webhook", h))
		s.TLSConfig = tlsConfig
		l.Servers = append(l.Servers, s)
	}
	b := cfg.Listeners.Broker
	if b.Enabled {
		token, e := readInventoryFile(b.Token.File, true, 4096)
		if e != nil {
			return e
		}
		key, e := readInventoryFile(b.SigningKey.File, true, 4096)
		if e != nil {
			return e
		}
		h, e := broker.New(broker.Options{Username: b.Username, Token: string(bytes.TrimSpace(token)), SigningKey: string(bytes.TrimSpace(key)), SCEPURL: b.SCEPURL, Provisioner: b.Provisioner})
		if e != nil {
			return e
		}
		pair, e := loadPair(b.CertFile, b.KeyFile.File)
		if e != nil {
			return e
		}
		s := boundedServer(b.Address, sdk.Handler("broker", h))
		s.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{pair}}
		l.Servers = append(l.Servers, s)
	}
	return nil
}

// This bounded authenticated self-probe exercises the bound policy handler and
// does not create or consume a TLS handoff or invoke an inventory/API lookup.
func probePolicyHandler(ctx context.Context, address string, token []byte) error {
	req, e := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+address+"/healthz", nil)
	if e != nil {
		return e
	}
	req.Header.Set("Authorization", "Bearer "+string(token))
	client := &http.Client{Timeout: time.Second, Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true}, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("policy health redirect refused") }}
	response, e := client.Do(req)
	if e != nil {
		return errors.New("local policy handler unavailable")
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusNoContent {
		return errors.New("local policy handler authentication failed")
	}
	return nil
}
