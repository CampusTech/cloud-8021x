// Package native supplies typed FreeRADIUS rendering and local health adapters.
package native

import (
	"bytes"
	"errors"
	"os"
	"os/user"
	"strconv"

	"github.com/CampusTech/cloud-8021x/internal/config"
	"github.com/CampusTech/cloud-8021x/internal/network"
	"github.com/CampusTech/cloud-8021x/internal/privileged/sources"
	"github.com/CampusTech/cloud-8021x/internal/storage/postgres"
	templates "github.com/CampusTech/cloud-8021x/internal/templates/freeradius"
)

// Render reads protected local credential references only. The caller is the
// root bootstrap helper; no cloud or database connection is made here.
func Render(cfg config.Config, generation string) (map[string][]byte, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	read := func(path string, owner int) (string, error) {
		b, e := network.ReadPrivate(path, owner)
		if e != nil || len(b) > 8192 {
			return "", errors.New("native credential unavailable")
		}
		return string(bytes.TrimSpace(b)), nil
	}
	app, e := user.Lookup(cfg.RuntimeUser)
	if e != nil {
		return nil, errors.New("native policy account unavailable")
	}
	uid, e := strconv.Atoi(app.Uid)
	if e != nil || uid <= 0 {
		return nil, errors.New("invalid native policy account")
	}
	return render(cfg, generation, func(path string) (string, error) {
		owner := os.Geteuid()
		if path == cfg.Listeners.Policy.Token.File || path == cfg.Bootstrap.HealthSecret.File {
			owner = uid
		}
		return read(path, owner)
	})
}

// RenderWithSecrets serializes a protected bootstrap candidate entirely from
// its already fetched in-memory credentials, before replacing any live files.
func RenderWithSecrets(cfg config.Config, generation string, credentials map[string][]byte) (map[string][]byte, error) {
	if e := cfg.Validate(); e != nil {
		return nil, e
	}
	return render(cfg, generation, func(path string) (string, error) {
		b, ok := credentials[path]
		if !ok || len(b) == 0 || len(b) > 8192 {
			return "", errors.New("required candidate credential missing")
		}
		return string(bytes.TrimSpace(b)), nil
	})
}
func render(cfg config.Config, generation string, read func(string) (string, error)) (map[string][]byte, error) {
	token, e := read(cfg.Listeners.Policy.Token.File)
	if e != nil {
		return nil, e
	}
	dsn, e := read(cfg.Database.NativeWriterDSN.File)
	if e != nil {
		return nil, e
	}
	conn, e := postgres.NativeConninfo(dsn, cfg.Database)
	if e != nil {
		return nil, e
	}
	sc, e := sources.FromConfig(cfg)
	if e != nil {
		return nil, e
	}
	if len(cfg.CA.RootFiles) != 1 {
		return nil, errors.New("native TLS requires one prepared CA bundle")
	}
	o := templates.Options{Host: cfg.Hostname, Generation: generation, ConfigDir: cfg.Backends.RadiusConfigDir, AuthDirectory: cfg.Paths.AuthLogDir, SpoolDirectory: cfg.Paths.AccountingSpoolDir, LeafDirectory: cfg.Backends.RadiusVerifyLeafDir, CertificateFile: cfg.CA.ServerCertFile, KeyFile: cfg.CA.ServerKeyFile.File, CAFile: cfg.CA.RootFiles[0], PolicyAddress: cfg.Listeners.Policy.Address, Bearer: token, NativeConninfo: conn, Legacy: cfg.Policy.IdentityMode == "legacy-serial", SourcesInclude: cfg.Network.Discovery.Enabled, SourceConfigSHA256: sc.Identity()}
	for _, client := range cfg.RadiusClients {
		secret, e := read(client.Secret.File)
		if e != nil {
			return nil, e
		}
		o.Clients = append(o.Clients, templates.Client{ID: client.ID, Location: client.LocationID, CIDRs: client.CIDRs, Secret: secret})
	}
	if cfg.Bootstrap.Project != "" {
		o.HealthAddress = cfg.Bootstrap.LocalAddress
		o.HealthPeer = cfg.Bootstrap.PeerAddress
		o.HealthSecret, e = read(cfg.Bootstrap.HealthSecret.File)
		if e != nil {
			return nil, e
		}
	}
	return templates.Render(o)
}
