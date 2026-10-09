//go:build linux

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/adapters/freeradius/native"
	"github.com/CampusTech/cloud-8021x/internal/adapters/freeradius/policy"
	"github.com/CampusTech/cloud-8021x/internal/adoption"
	"github.com/CampusTech/cloud-8021x/internal/config"
	"github.com/CampusTech/cloud-8021x/internal/domain"
	"golang.org/x/sys/unix"
)

const sourceConfig = "/etc/cloud8021x-task11-source.yaml"

func sourceConfiguration() (config.Config, error) {
	var c config.Config
	parent, err := privateParent(sourceConfig, 0)
	if err != nil {
		return c, err
	}
	defer func() { _ = unix.Close(parent) }()
	fd, err := unix.Openat(parent, filepath.Base(sourceConfig), unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return c, err
	}
	f := os.NewFile(uintptr(fd), sourceConfig)
	defer func() { _ = f.Close() }()
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Uid != 0 || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Mode&0022 != 0 || st.Nlink != 1 {
		return c, errors.New("source configuration must be a protected original fixture file")
	}
	c, err = config.Decode(f)
	if err != nil {
		return c, err
	}
	return c, validateSourceScope(c)
}

const sourceProjection = "/etc/cloud8021x-task11-source-provenance.json"

func readSourceProjection() (sourceProvenance, error) {
	var p sourceProvenance
	parent, err := privateParent(sourceProjection, 0)
	if err != nil {
		return p, err
	}
	defer func() { _ = unix.Close(parent) }()
	fd, err := unix.Openat(parent, filepath.Base(sourceProjection), unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return p, err
	}
	f := os.NewFile(uintptr(fd), sourceProjection)
	defer func() { _ = f.Close() }()
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Uid != 0 || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Mode&0777 != 0444 || st.Nlink != 1 {
		return p, errors.New("source projection must be root-owned0444 regular file")
	}
	raw, err := boundedInput(f, 16<<10)
	if err != nil {
		return p, err
	}
	if domain.DecodeJSONStrict(raw, &p) != nil {
		return p, errors.New("invalid protected source projection")
	}
	canonical, err := json.Marshal(p.Snapshot)
	if err != nil {
		return p, err
	}
	return p, validateBoundSourceCache(canonical, p)
}
func verifyRootSourceProvenance() error {
	if os.Geteuid() != 0 {
		return errors.New("root original-state preflight required")
	}
	p, err := readSourceProjection()
	if err != nil {
		return err
	}
	state, err := readPrivate("/var/lib/cloud-8021x/certificate-state.json", 16<<20, 0)
	if err != nil {
		return err
	}
	if adoption.Digest(state) != p.CertificateStateSHA256 {
		return errors.New("retained private certificate state differs from approved source projection")
	}
	canonical, err := json.Marshal(p.Snapshot)
	if err != nil {
		return err
	}
	actual, err := deriveSourceProvenance(canonical, state)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(actual, p) {
		return errors.New("approved original enrollment projection differs")
	}
	raw, err := readPublic("/etc/freeradius/3.0/device-policy-cache.json", domain.MaxSnapshotBytes)
	if err != nil {
		return err
	}
	return validateBoundSourceCache(raw, p)
}
func sourcePolicy(ctx context.Context) error {
	if err := fixtureMarker(); err != nil {
		return err
	}
	u, err := user.Lookup("cloud8021x")
	if err != nil {
		return err
	}
	uid, err := strconv.Atoi(u.Uid)
	if err != nil || uid <= 0 || os.Geteuid() != uid {
		return errors.New("synthetic source endpoint must run as cloud8021x, never root")
	}
	c, err := sourceConfiguration()
	if err != nil {
		return err
	}
	hostname, err := os.Hostname()
	if err != nil || hostname != c.Hostname {
		return errors.New("source endpoint physical host differs")
	}
	raw, err := readPublic(c.Paths.InventoryFile, domain.MaxSnapshotBytes)
	if err != nil {
		return err
	}
	projection, err := readSourceProjection()
	if err != nil {
		return err
	}
	if err = validateBoundSourceCache(raw, projection); err != nil {
		return err
	}
	service, handler, err := policy.FromConfig(c, nil)
	if err != nil {
		return err
	}
	validated, err := domain.DecodeSnapshot(bytes.NewReader(raw))
	if err != nil {
		return err
	}
	if err = service.Snapshots().Set(validated); err != nil {
		return err
	}
	server := handler.Server(c.Listeners.Policy.Address)
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	done := make(chan struct{})
	failure := make(chan error, 1)
	go func() {
		defer close(done)
		tick := time.NewTicker(time.Second)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
				b, e := readPublic(c.Paths.InventoryFile, domain.MaxSnapshotBytes)
				if e != nil || validateBoundSourceCache(b, projection) != nil {
					failure <- errors.New("original source cache provenance failed")
					// A provenance mismatch is a failed source fixture, not a
					// reason to keep authorizing from a hidden old cache.
					_ = service.Snapshots().Set(domain.Snapshot{Version: 2, Identities: map[string]*domain.DeviceRecord{}, Certificates: map[string]*domain.DeviceRecord{}, HardwareSerials: map[string]*domain.DeviceRecord{}})
					cancel()
					return
				}
				s, e := domain.DecodeSnapshot(bytes.NewReader(b))
				if e == nil {
					_ = service.Snapshots().Set(s)
				}
			}
		}
	}()
	go func() {
		<-ctx.Done()
		shutdown, c := context.WithTimeout(context.Background(), 5*time.Second)
		defer c()
		_ = server.Shutdown(shutdown)
	}()
	err = server.ListenAndServe()
	cancel()
	<-done
	select {
	case e := <-failure:
		return e
	default:
	}
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
func sourceRender() error {
	if err := fixtureGuard(); err != nil {
		return err
	}
	c, err := sourceConfiguration()
	if err != nil {
		return err
	}
	if err = verifyRootSourceProvenance(); err != nil {
		return err
	}
	files, err := native.Render(c, "7a5110a161a10001")
	if err != nil {
		return err
	}
	root := control + "/source-native"
	if err = os.Mkdir(root, 0700); err != nil {
		return err
	}
	for path, data := range files {
		if filepath.IsAbs(path) || filepath.Clean(path) != path || path == ".." || strings.HasPrefix(path, "../") || len(path) > 512 {
			return errors.New("unexpected native output path")
		}
		full := filepath.Join(root, path)
		if err = os.MkdirAll(filepath.Dir(full), 0700); err != nil {
			return err
		}
		if err = atomicPrivate(full, data, 0); err != nil {
			return err
		}
	}
	unit := []byte("[Unit]\nDescription=Task11 synthetic legacy-compatible source policy (development only)\nAfter=network.target\n[Service]\nType=simple\nUser=cloud8021x\nGroup=cloud8021x\nExecStart=/usr/local/libexec/task11-acceptance source-policy\nNoNewPrivileges=yes\nPrivateTmp=yes\nProtectSystem=strict\nProtectHome=yes\nReadWritePaths=/run/radius-certificate-bindings\nRestart=on-failure\n[Install]\nWantedBy=multi-user.target\n")
	if err = atomicPrivate(control+"/source-policy.service", unit, 0); err != nil {
		return err
	}
	writer := []byte("[Unit]\nDescription=Task11 synthetic original source writer workload\n[Service]\nType=oneshot\nExecStart=/usr/local/libexec/task11-acceptance source-writer\n")
	timer := []byte("[Unit]\nDescription=Task11 synthetic original source writer timer\n[Timer]\nOnBootSec=10s\nOnUnitActiveSec=10s\nUnit=radius-source-refresh.service\n[Install]\nWantedBy=timers.target\n")
	if err = atomicPrivate(control+"/radius-source-refresh.service", writer, 0); err != nil {
		return err
	}
	return atomicPrivate(control+"/radius-source-refresh.timer", timer, 0)
}

// This workload proves real scheduler/lock fencing only. It never renews a
// certificate, changes original observation times or impersonates a vendor API.
func sourceWriter(ctx context.Context) error {
	if err := fixtureGuard(); err != nil {
		return err
	}
	hostname, err := os.Hostname()
	if err != nil || (hostname != "task11-blue-primary" && hostname != "task11-blue-secondary") {
		return errors.New("synthetic writer requires original physical node")
	}
	parent, err := privateParent("/run/radius-sources.lock", 0)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(parent) }()
	fd, err := unix.Openat(parent, "radius-sources.lock", unix.O_RDWR|unix.O_CREAT|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(fd) }()
	if err = fileStat(fd, 0, 0); err != nil {
		return err
	}
	if err = unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return err
	}
	for range 5 {
		if err = atomicPrivate(control+"/synthetic-writer-heartbeat", []byte(time.Now().UTC().Format(time.RFC3339Nano)+"\n"), 0); err != nil {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
	}
	return nil
}
