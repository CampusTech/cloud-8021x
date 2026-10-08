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
	token, e := read(cfg.Listeners.Policy.Token.File, uid)
	if e != nil {
		return nil, e
	}
	dsn, e := read(cfg.Database.NativeWriterDSN.File, os.Geteuid())
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
		secret, e := read(client.Secret.File, os.Geteuid())
		if e != nil {
			return nil, e
		}
		o.Clients = append(o.Clients, templates.Client{ID: client.ID, Location: client.LocationID, CIDRs: client.CIDRs, Secret: secret})
	}
	return templates.Render(o)
}

// ParseCounter words are deliberately never parsed here. Native SQL stores
// nullable text/counts; the shared ledger owns normalization and quarantine.
