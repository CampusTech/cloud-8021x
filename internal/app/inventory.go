package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/CampusTech/cloud-8021x/internal/adapters/fleet"
	"github.com/CampusTech/cloud-8021x/internal/config"
	"github.com/CampusTech/cloud-8021x/internal/domain"
	"github.com/CampusTech/cloud-8021x/internal/inventory"
	inventoryjob "github.com/CampusTech/cloud-8021x/internal/jobs/inventory"
	"github.com/CampusTech/cloud-8021x/internal/storage/postgres"
	"golang.org/x/sys/unix"
)

// InventoryServiceFromConfig constructs observer and optional maintainer with
// separate protected credentials. Serve and the schedule runner in Task9 share
// this real service and the policy SnapshotStore. HTTP injection is for local
// fixtures/custom trusted transport, never a certificate-verification bypass.
func InventoryServiceFromConfig(ctx context.Context, cfg config.Config, store *domain.SnapshotStore, dryRun bool, hc *http.Client) (*inventoryjob.Service, func(), error) {
	if !cfg.Inventory.Enabled || cfg.Inventory.Provider != "fleet" {
		return nil, nil, errors.New("fleet inventory must be enabled")
	}
	token, err := readInventoryFile(cfg.Inventory.Fleet.ObserverToken.File, true, 4096)
	if err != nil {
		return nil, nil, err
	}
	observerClient, err := fleet.NewClient(cfg.Inventory.Fleet.BaseURL, string(bytes.TrimSpace(token)), hc, cfg.Inventory.Fleet.Timeout)
	if err != nil {
		return nil, nil, err
	}
	observer := &fleet.Observer{Client: observerClient, HostIDs: cfg.Inventory.Fleet.HostIDs, TeamIDs: cfg.Inventory.Fleet.TeamIDs, AllowLabel: cfg.Inventory.Fleet.AllowLabel}
	service := &inventoryjob.Service{Provider: observer, Scope: domain.InventoryScope{ProviderID: "fleet", IDs: cfg.Inventory.Fleet.HostIDs}, Store: store, Path: cfg.Paths.InventoryFile}
	cleanup := func() {}
	if !dryRun && cfg.Inventory.Fleet.CacheFile != "" {
		cacheIdentity, _ := json.Marshal(struct {
			Base, Token, Label string
			Hosts, Teams       []string
		}{cfg.Inventory.Fleet.BaseURL, string(bytes.TrimSpace(token)), cfg.Inventory.Fleet.AllowLabel, cfg.Inventory.Fleet.HostIDs, cfg.Inventory.Fleet.TeamIDs})
		digest := sha256.Sum256(cacheIdentity)
		service.Provider = &inventory.CachedProvider{Key: hex.EncodeToString(digest[:]), Provider: observer, Path: cfg.Inventory.Fleet.CacheFile, MaxAge: cfg.Schedules.Inventory}
	}
	if !cfg.Inventory.Fleet.ManagedCertificates || dryRun {
		return service, cleanup, nil
	}
	maintainer, err := readInventoryFile(cfg.Inventory.Fleet.MaintainerToken.File, true, 4096)
	if err != nil {
		return nil, nil, err
	}
	if bytes.Equal(bytes.TrimSpace(token), bytes.TrimSpace(maintainer)) {
		return nil, nil, errors.New("fleet observer and maintainer require separate credentials")
	}
	maintainerClient, err := fleet.NewClient(cfg.Inventory.Fleet.BaseURL, string(bytes.TrimSpace(maintainer)), hc, cfg.Inventory.Fleet.Timeout)
	if err != nil {
		return nil, nil, err
	}
	bundle, err := readInventoryFile(cfg.Inventory.Fleet.ClientCAFile, false, 1<<20)
	if err != nil {
		return nil, nil, err
	}
	trust, err := fleet.NewTrust(bundle)
	if err != nil {
		return nil, nil, err
	}
	dsn, err := readInventoryFile(cfg.Database.RuntimeDSN.File, true, 64<<10)
	if err != nil {
		return nil, nil, err
	}
	repository, err := postgres.New(ctx, strings.TrimSpace(string(dsn)), cfg.Database)
	if err != nil {
		return nil, nil, err
	}
	service.Certificates = &fleet.Collector{ReloadTrust: func() (*fleet.Trust, error) {
		publicBundle, err := readInventoryFile(cfg.Inventory.Fleet.ClientCAFile, false, 1<<20)
		if err != nil {
			return nil, err
		}
		return fleet.NewTrust(publicBundle)
	}, Maintainer: maintainerClient, Repository: repository.ForTransition(cfg.StateTransition), Trust: trust, Owner: cfg.InstanceID, Options: fleet.CollectionOptions{Cadence: cfg.Inventory.Fleet.PollInterval, MaxAge: cfg.Policy.CertificateMaxAge, SCEPProfiles: cfg.Inventory.Fleet.SCEPProfileUUIDs, ACMEProfiles: cfg.Inventory.Fleet.ACMEProfileUUIDs}}
	return service, repository.Close, nil
}
func readInventoryFile(path string, secret bool, limit int64) ([]byte, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, errors.New("inventory credential or trust file unavailable")
	}
	file := os.NewFile(uintptr(fd), path)
	defer func() { _ = file.Close() }()
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 || st.Mode&0022 != 0 || (secret && st.Mode&0777 != 0600) || (st.Uid != uint32(os.Geteuid()) && st.Uid != 0) {
		return nil, errors.New("inventory credentials must be private regular files and trust non-writable")
	}
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || len(data) == 0 || int64(len(data)) > limit {
		return nil, errors.New("inventory credential or trust file invalid")
	}
	return data, nil
}
