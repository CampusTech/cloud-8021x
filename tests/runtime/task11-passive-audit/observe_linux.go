//go:build linux

package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"debug/buildinfo"
	"errors"
	"net"
	"os"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/config"
	"github.com/CampusTech/cloud-8021x/internal/domain"
	"github.com/CampusTech/cloud-8021x/internal/privileged/host"
	"github.com/CampusTech/cloud-8021x/internal/templates/systemd"
	"github.com/CampusTech/cloud-8021x/tests/runtime/task11-passive-audit/contract"
)

func observe(ctx context.Context, r contract.Request, requestHash string) (out contract.Result, err error) {
	if os.Geteuid() != 0 || os.Getuid() != 0 || runtime.GOOS != "linux" {
		return out, errors.New("actual root Linux node required")
	}
	out = contract.Result{Schema: 1, RequestSHA256: requestHash, Node: r.Node, Phase: r.Phase, ObservedAt: time.Now().UTC(), ApplicationSHA256: r.ApplicationSHA256, ApplicationSourceSHA: r.ApplicationSourceSHA, ConfigSHA256: r.ConfigSHA256, ControllerSHA256: r.ControllerSHA256, ObserverSHA256: r.ObserverSHA256, SeedSHA256: r.SeedSHA256, OriginalSeedSHA256: r.OriginalSeedSHA256, Pin: r.Pin, Preserved: map[string]contract.File{}, State: map[string]contract.File{}}
	marker, _, e := readProtected(fileRule{path: "/etc/cloud8021x-task11-fixture", uid: 0, gid: 0, mode: 0600, max: 64})
	if e != nil || string(marker) != "synthetic-only-v1\n" {
		return out, errors.New("protected synthetic marker required")
	}
	out.Identity, e = identity(r)
	if e != nil {
		return out, e
	}
	actualExe, e := os.Executable()
	if e != nil || actualExe != contract.Executable {
		return out, errors.New("fixed observer executable required")
	}
	for _, p := range []struct{ path, hash string }{{contract.Executable, r.ObserverSHA256}, {"/usr/local/libexec/task11-acceptance", r.ControllerSHA256}, {"/usr/local/bin/cloud-8021x", r.ApplicationSHA256}} {
		raw, f, e := readProtected(fileRule{path: p.path, uid: 0, gid: 0, mode: 0755, max: 256 << 20})
		if e != nil || f.SHA256 != p.hash {
			clear(raw)
			return out, errors.New("installed executable pin differs")
		}
		if p.path == "/usr/local/bin/cloud-8021x" {
			info, e := buildinfo.Read(bytes.NewReader(raw))
			if e != nil {
				return out, errors.New("actual application build metadata unavailable")
			}
			settings := map[string]string{}
			for _, s := range info.Settings {
				settings[s.Key] = s.Value
			}
			if settings["vcs.revision"] != r.ApplicationSourceSHA || settings["vcs.modified"] != "false" || settings["GOOS"] != "linux" || settings["GOARCH"] != runtime.GOARCH {
				return out, errors.New("application clean source/platform pin differs")
			}
		}
		clear(raw)
		out.State[p.path] = f
	}
	installed, f, e := readProtected(fileRule{path: "/etc/cloud-8021x/config.yaml", uid: 0, gid: 0, mode: 0600, max: config.MaxConfigBytes})
	if e != nil || f.SHA256 != r.ConfigSHA256 {
		return out, errors.New("installed enrolled config differs")
	}
	defer clear(installed)
	staged, sf, e := readProtected(fileRule{path: "/var/cache/cloud-8021x/artifacts/config.yaml", uid: 0, gid: 0, mode: 0600, max: config.MaxConfigBytes})
	if e != nil || !bytes.Equal(installed, staged) {
		clear(staged)
		return out, errors.New("staged and installed config differ")
	}
	clear(staged)
	out.State["installed-config"] = f
	out.State["staged-config"] = sf
	cfg, e := config.Decode(bytes.NewReader(installed))
	if e != nil || cfg.Deployment.ID != "task11-green" || cfg.Deployment.Instance != "task11-"+r.Node || cfg.InstanceID != "radius-"+strings.TrimPrefix(r.Node, "green-") || cfg.Hostname != "task11-"+r.Node || cfg.Database.Name != "cloud8021x_task11_green" || len(cfg.Network.Providers) != 0 {
		return out, errors.New("synthetic protected configuration identity differs")
	}
	manifestRaw, mf, e := readProtected(fileRule{path: "/var/cache/cloud-8021x/artifacts/manifest.json", uid: 0, gid: 0, mode: 0600, max: 1 << 20})
	if e != nil {
		return out, e
	}
	var artifacts host.Manifest
	if domain.DecodeJSONStrict(manifestRaw, &artifacts) != nil || artifacts.Validate(runtime.GOARCH) != nil || artifacts.ApplicationSHA256 != r.ApplicationSHA256 || artifacts.ConfigSHA256 != r.ConfigSHA256 {
		return out, errors.New("actual authenticated artifact manifest differs")
	}
	clear(manifestRaw)
	out.State["artifact-manifest"] = mf
	seedRaw, seedFile, e := readProtected(fileRule{path: contract.SeedManifest, uid: 0, gid: 0, mode: 0600, max: 16 << 10})
	if e != nil || seedFile.SHA256 != r.SeedSHA256 {
		return out, errors.New("independent prepared seed manifest pin differs")
	}
	var seed contract.Manifest
	if domain.DecodeJSONStrict(seedRaw, &seed) != nil || contract.ValidateManifest(seed, r) != nil {
		return out, errors.New("protected seed contract differs")
	}
	clear(seedRaw)
	out.State["seed-manifest"] = seedFile
	key, _, e := readProtected(fileRule{path: "/var/lib/cloud-8021x-bootstrap/parallel-source.key", uid: 0, gid: 0, mode: 0600, max: 64})
	if e != nil || len(key) != ed25519.PrivateKeySize {
		return out, errors.New("actual enrolled source key unavailable")
	}
	public := ed25519.PrivateKey(key).Public().(ed25519.PublicKey)
	if len(public) != 32 {
		clear(key)
		return out, errors.New("source key invalid")
	}
	derived := ed25519.NewKeyFromSeed(key[:32])
	if !bytes.Equal(derived, key) || fmtHex(public) != r.Pin {
		clear(key)
		clear(derived)
		return out, errors.New("actual enrolled node pin differs")
	}
	clear(key)
	clear(derived)
	if absence(host.ParallelActiveFile) != nil || absence(host.ParallelPublicActivationFile) != nil {
		return out, errors.New("product activation artifacts present or uncertain")
	}
	known, e := host.KnownInstallation()
	if e != nil || !known {
		return out, errors.New("actual completed product generation unavailable")
	}
	accounts, e := host.ReadAccounts()
	if e != nil {
		return out, e
	}
	receipt, installedTrust, e := host.ParallelInstalledReceipt(cfg, r.ApplicationSHA256)
	if e != nil || receipt == "" || installedTrust != seed.Slots["client-trust"] {
		return out, errors.New("actual prepared physical receipt/trust differs")
	}
	if e = credentials(cfg, accounts, out.State, receipt); e != nil {
		return out, e
	}
	paths := slotRules(cfg, accounts)
	if len(paths) != len(contract.Slots) {
		return out, errors.New("closed installed slot mapping incomplete")
	}
	contents := map[string][]byte{}
	defer func() {
		for _, v := range contents {
			clear(v)
		}
	}()
	for _, name := range contract.Slots {
		rule, ok := paths[name]
		if !ok {
			return out, errors.New("unknown installed seed slot")
		}
		raw, f, e := readProtected(rule)
		if e != nil || f.SHA256 != seed.Slots[name] {
			clear(raw)
			return out, errors.New("actual preserved slot differs: " + name)
		}
		contents[name] = raw
		out.Preserved[name] = f
	}
	for _, pair := range [][2]string{{"native-server", "native-server-key"}, {"webhook-cache", "webhook-cache-key"}, {"webhook-public", "webhook-key"}, {"ec-decrypter", "ec-decrypter-key"}, {"rsa-decrypter", "rsa-decrypter-key"}} {
		if _, e = tls.X509KeyPair(contents[pair[0]], contents[pair[1]]); e != nil {
			return out, errors.New("preserved certificate/private-key identity differs")
		}
	}
	if !bytes.Equal(contents["class-key"], contents["legacy-class-key"]) || out.Preserved["postgres-ca"].SHA256 != artifacts.PostgresCASHA256 {
		return out, errors.New("preserved Class or SQL trust differs")
	}
	rendered, e := systemd.Render()
	if e != nil {
		return out, e
	}
	for _, b := range host.ParallelPassiveFiles() {
		raw, _, e := readProtected(fileRule{path: b.Path, uid: 0, gid: 0, mode: uint32(b.Mode), max: 4096})
		if e != nil || !bytes.Equal(raw, b.Data) {
			return out, errors.New("actual passive barrier differs")
		}
		clear(raw)
	}
	for _, name := range append(slices.Clone(contract.Services), contract.Timers...) {
		path := "/etc/systemd/system/" + name
		if r.Phase == "deactivated" && contract.WorkerMasked(name) {
			if e = protectedMask(path); e != nil {
				return out, e
			}
			continue
		}
		if name == "freeradius.service" {
			path = "/etc/systemd/system/freeradius.service.d/cloud8021x.conf"
		}
		expected, ok := rendered[path]
		if !ok {
			return out, errors.New("shipping unit render contract unavailable")
		}
		raw, _, e := readProtected(fileRule{path: path, uid: 0, gid: 0, mode: 0644, max: 65536})
		if e != nil || !bytes.Equal(raw, expected) {
			return out, errors.New("installed passive unit differs")
		}
		clear(raw)
	}
	out.Units, e = units(ctx)
	if e != nil || contract.ValidateUnits(out.Units, r.Phase) != nil {
		return out, errors.New("actual systemd passive state differs")
	}
	out.Processes, e = processes()
	if e != nil {
		return out, e
	}
	ports := []uint16{1812, 1813, 18122, 18123, 8443, 8444, 9090, 9091, 55681}
	for _, a := range []string{cfg.Listeners.Policy.Address, cfg.Listeners.Webhook.Address, cfg.Listeners.Broker.Address, cfg.Listeners.HealthAddress, cfg.Listeners.MetricsAddress} {
		if a == "" {
			continue
		}
		_, p, e := net.SplitHostPort(a)
		if e != nil {
			return out, errors.New("configured admission address invalid")
		}
		n, e := strconv.ParseUint(p, 10, 16)
		if e != nil {
			return out, e
		}
		ports = append(ports, uint16(n))
	}
	out.Sockets, e = sockets()
	if e != nil || contract.ValidateSockets(out.Sockets, ports) != nil {
		return out, errors.New("actual listeners/peer sockets not passive")
	}
	out.Collector, e = collector()
	if e != nil {
		return out, e
	}
	out.SQL, e = observeSQL(ctx, cfg, r, seed)
	if e != nil || contract.ValidateSQL(out.SQL, r.Phase) != nil {
		return out, errors.New("actual read-only SQL passive state differs")
	}
	localPrepared := false
	for _, n := range out.SQL.Prepared {
		if n.Role == cfg.InstanceID && n.Receipt == receipt && n.TrustSHA256 == installedTrust {
			localPrepared = true
		}
	}
	if !localPrepared {
		return out, errors.New("actual local physical preparation differs from SQL")
	}
	if r.Phase == "deactivated" {
		binding, e := expectedBinding(cfg, r)
		if e != nil {
			return out, e
		}
		out.WorkerFenceSHA256, e = host.VerifyDaemonWorkerFence(ctx, cfg.StateTransition, cfg.InstanceID, binding.ConfigSHA256, &host.RadiusBackend{})
		if e != nil {
			return out, errors.New("actual persistent worker fence not verified")
		}
		matched := false
		for _, f := range out.SQL.WorkerFences {
			if f.Node == cfg.InstanceID && f.ReceiptSHA256 == out.WorkerFenceSHA256 {
				matched = true
			}
		}
		if !matched {
			return out, errors.New("actual local worker fence differs from SQL")
		}
	}
	again, e := identity(r)
	if e != nil || again.BootID != out.Identity.BootID || again.PID1Start != out.Identity.PID1Start {
		return out, errors.New("boot identity changed during observation")
	}
	after, e := units(ctx)
	if e != nil || contract.ValidateUnits(after, r.Phase) != nil {
		return out, errors.New("systemd passive state changed during observation")
	}
	if _, e = processes(); e != nil {
		return out, e
	}
	afterSockets, e := sockets()
	if e != nil || contract.ValidateSockets(afterSockets, ports) != nil {
		return out, errors.New("passive socket state changed during observation")
	}

	if e = ctx.Err(); e != nil {
		return out, errors.New("observation context expired")
	}
	if absence(host.ParallelActiveFile) != nil || absence(host.ParallelPublicActivationFile) != nil {
		return out, errors.New("activation artifacts appeared during observation")
	}
	for _, name := range contract.Slots {
		raw, f, e := readProtected(paths[name])
		clear(raw)
		if e != nil || f.SHA256 != out.Preserved[name].SHA256 {
			return out, errors.New("preserved identity changed during observation")
		}
	}
	for path, f := range out.State {
		var actualPath string
		switch path {
		case "installed-config":
			actualPath = "/etc/cloud-8021x/config.yaml"
		case "staged-config":
			actualPath = "/var/cache/cloud-8021x/artifacts/config.yaml"
		case "artifact-manifest":
			actualPath = "/var/cache/cloud-8021x/artifacts/manifest.json"
		case "seed-manifest":
			actualPath = contract.SeedManifest
		default:
			actualPath = strings.TrimPrefix(path, "credential:")
		}
		raw, again, e := readProtected(fileRule{path: actualPath, uid: int(f.UID), gid: int(f.GID), mode: f.Mode, max: f.Bytes})
		clear(raw)
		if e != nil || again.SHA256 != f.SHA256 || again.Device != f.Device || again.Inode != f.Inode {
			return out, errors.New("completed installed state changed during observation")
		}
	}
	if e = ctx.Err(); e != nil {
		return out, errors.New("observation context expired")
	}
	return out, nil
}
func fmtHex(raw []byte) string {
	const chars = "0123456789abcdef"
	b := make([]byte, len(raw)*2)
	for i, v := range raw {
		b[i*2] = chars[v>>4]
		b[i*2+1] = chars[v&15]
	}
	return string(b)
}
func credentials(cfg config.Config, a host.Accounts, state map[string]contract.File, reference string) error {
	layout := []host.File{}
	for _, ref := range cfg.Bootstrap.Secrets {
		uid, gid := 0, 0
		switch ref.Owner {
		case "runtime":
			uid, gid = a.RuntimeUID, a.RuntimeGID
		case "collector":
			uid, gid = a.CollectorUID, a.CollectorGID
		case "root":
		default:
			return errors.New("unknown credential owner")
		}
		layout = append(layout, host.File{Path: ref.File, UID: uid, GID: gid, Mode: 0600})
	}
	layout = append(layout, host.File{Path: "/run/cloud-8021x/credentials/webhook.key", UID: a.RuntimeUID, GID: a.RuntimeGID, Mode: 0600}, host.File{Path: "/run/cloud-8021x-collector/datadog.env", UID: a.CollectorUID, GID: a.CollectorGID, Mode: 0600})
	values, e := host.CommittedCredentials(layout)
	if e != nil {
		return errors.New("actual committed credential/generation bindings invalid")
	}
	defer func() {
		for _, v := range values {
			clear(v)
		}
	}()
	for _, f := range layout {
		raw, meta, e := readProtected(fileRule{path: f.Path, uid: f.UID, gid: f.GID, mode: uint32(f.Mode), max: 1 << 20})
		if e != nil || !bytes.Equal(raw, values[f.Path]) {
			clear(raw)
			return errors.New("actual restored boot credential differs")
		}
		clear(raw)
		state["credential:"+f.Path] = meta
	}
	for _, path := range []string{"/var/lib/cloud-8021x-bootstrap/current.json", "/var/lib/cloud-8021x-bootstrap/active-credentials.json", "/run/cloud-8021x-root/credential-set.json"} {
		raw, f, e := readProtected(fileRule{path: path, uid: 0, gid: 0, mode: 0600, max: 4 << 20})
		if e != nil {
			return e
		}

		if path == "/run/cloud-8021x-root/credential-set.json" {
			var marker struct{ Reference, SHA256 string }
			if domain.DecodeJSONStrict(raw, &marker) != nil || marker.Reference != reference || marker.SHA256 != state["/var/lib/cloud-8021x-bootstrap/active-credentials.json"].SHA256 {
				clear(raw)
				return errors.New("actual volatile boot marker differs from completed cache")
			}
		}
		clear(raw)
		state[path] = f
	}
	return nil
}
func slotRules(c config.Config, a host.Accounts) map[string]fileRule {
	out := map[string]fileRule{}
	add := func(n, p string, uid, gid int, mode uint32) {
		out[n] = fileRule{path: p, uid: uid, gid: gid, mode: mode, max: 4 << 20}
	}
	for _, kind := range []string{"ec", "rsa"} {
		base := "/etc/step-ca"
		template := "wifi-acme.tpl"
		if kind == "rsa" {
			base += "-rsa"
			template = "wifi-scep.tpl"
		}
		for n, p := range map[string]string{"root": "/certs/root_ca.crt", "intermediate": "/certs/intermediate_ca.crt", "decrypter": "/certs/scep_decrypter.crt", "decrypter-key": "/secrets/scep_decrypter_key", "config": "/config/ca.json", "template": "/templates/x509/" + template} {
			add(kind+"-"+n, base+p, 0, 0, 0600)
		}
	}
	add("native-server", "/etc/freeradius/3.0/certs/server-cert.pem", 0, a.NativeGID, 0640)
	add("native-server-key", "/etc/freeradius/3.0/certs/server-key.pem", 0, a.NativeGID, 0640)
	for n, p := range map[string]string{"client-trust": "/etc/cloud-8021x/client-cas.pem", "server-cache": "/etc/cloud-8021x/radius-server.pem", "webhook-cache": "/etc/acme-authz-webhook/server.crt", "webhook-public": "/etc/cloud-8021x/webhook.crt", "postgres-ca": "/etc/cloud-8021x/postgres-ca.pem"} {
		add(n, p, 0, 0, 0644)
	}
	add("webhook-cache-key", "/etc/acme-authz-webhook/server.key", 0, 0, 0600)
	add("webhook-key", "/run/cloud-8021x/credentials/webhook.key", a.RuntimeUID, a.RuntimeGID, 0600)
	add("class-key", c.Policy.ClassSigningKey.File, a.RuntimeUID, a.RuntimeGID, 0600)
	add("legacy-class-key", "/run/radius-accounting-key", a.RuntimeUID, a.RuntimeGID, 0600)
	add("inventory", "/var/lib/cloud-8021x/inventory.json", a.RuntimeUID, a.RuntimeGID, 0644)
	return out
}
