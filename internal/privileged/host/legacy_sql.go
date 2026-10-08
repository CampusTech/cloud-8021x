package host

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/domain"
	"github.com/CampusTech/cloud-8021x/internal/migration"
	"github.com/go-sql-driver/mysql"
	"golang.org/x/sys/unix"
)

const legacySQLSocket = "/run/mysqld/mysqld.sock"

type legacySQLCapture struct {
	Transition, Node, ConfigSHA256, WriterSHA256 string
	NativeManifest                               json.RawMessage
	NativeConfig, SQLConfig                      []byte
	SQL                                          migration.LegacySQL
}

func legacySQLConnector() (*mysql.Config, error) {
	uid, _, e := identity("mysql")
	if e != nil {
		return nil, e
	}
	cfg := mysql.NewConfig()
	cfg.User = "root"
	cfg.Net = "unix"
	cfg.Addr = legacySQLSocket
	cfg.DBName = "radius"
	cfg.Timeout = 5 * time.Second
	cfg.ReadTimeout = 10 * time.Second
	cfg.WriteTimeout = 5 * time.Second
	cfg.DialFunc = func(ctx context.Context, network, address string) (net.Conn, error) {
		if network != "unix" || address != legacySQLSocket {
			return nil, errors.New("fixed legacy SQL socket required")
		}
		parent, e := openParentDescriptor(legacySQLSocket, uid, false)
		if e != nil {
			return nil, e
		}
		defer func() { _ = unix.Close(parent) }()
		var before, after unix.Stat_t
		if unix.Fstatat(parent, "mysqld.sock", &before, unix.AT_SYMLINK_NOFOLLOW) != nil || before.Mode&unix.S_IFMT != unix.S_IFSOCK || before.Nlink != 1 || int(before.Uid) != uid {
			return nil, errors.New("unsafe legacy SQL socket")
		}
		conn, e := (&net.Dialer{}).DialContext(ctx, "unix", fmt.Sprintf("/proc/self/fd/%d/mysqld.sock", parent))
		if e != nil {
			return nil, errors.New("legacy SQL socket unavailable; absence unproven")
		}
		if unix.Fstatat(parent, "mysqld.sock", &after, unix.AT_SYMLINK_NOFOLLOW) != nil || before.Dev != after.Dev || before.Ino != after.Ino || proveSQLPeer(conn, uid) != nil {
			_ = conn.Close()
			return nil, errors.New("legacy SQL socket identity changed")
		}
		return conn, nil
	}
	return cfg, nil
}

// CaptureLegacySQL never controls a service. The caller holds the original
// operation flock and live maintenance gate, with both writer fences proven.
func CaptureLegacySQL(ctx context.Context, id, node, hash, writer string) error {
	return captureLegacySQL(ctx, id, node, hash, writer, &RadiusBackend{})
}
func captureLegacySQL(ctx context.Context, id, node, hash, writer string, b *RadiusBackend) error {
	return inspectLegacySQL(ctx, id, node, hash, writer, b, true)
}
func PreflightLegacySQL(ctx context.Context, id, node, hash, writer string) error {
	return inspectLegacySQL(ctx, id, node, hash, writer, &RadiusBackend{}, false)
}
func inspectLegacySQL(ctx context.Context, id, node, hash, writer string, b *RadiusBackend, captureOriginal bool) error {
	if os.Geteuid() != 0 {
		return errors.New("root original SQL capture required")
	}
	dir, e := writerReceiptDirectory(id)
	if e != nil {
		return e
	}
	receipt, e := readPrivateCache(filepath.Join(dir, "receipt.json"), 16<<20)
	if e != nil || digestBytes(receipt) != writer {
		return errors.New("original SQL writer receipt unavailable")
	}
	r, e := decodeWriterReceipt(receipt, id)
	if e != nil || r.Node != node || r.ConfigSHA256 != hash {
		return errors.New("original SQL writer binding differs")
	}
	if e = verifyWriterMasks(r); e != nil {
		return e
	}
	if e = writerUnitsQuiescent(ctx, b.command, legacyWriterUnits); e != nil {
		return e
	}
	if e = checkObservedWriterProcesses(r.Processes); e != nil {
		return e
	}
	active, e := b.Running(ctx)
	if e != nil || active {
		return errors.New("old native SQL producer must already be proven stopped before capture")
	}
	if e = proveNativeProcessesGone(r.NativeUID); e != nil {
		return e
	}
	release, e := lockLegacyWriters()
	if e != nil {
		return e
	}
	defer release()
	manifest, e := nativeTreeManifest(radiusDirectory)
	if e != nil {
		return e
	}
	capture := legacySQLCapture{Transition: id, Node: node, ConfigSHA256: hash, WriterSHA256: writer, NativeManifest: manifest}
	for path, target := range map[string]*[]byte{radiusDirectory + "/radiusd.conf": &capture.NativeConfig, radiusDirectory + "/mods-available/sql": &capture.SQLConfig} {
		saved, e := snapshotUsing(File{Path: path, UID: r.NativeUID}, func(path string, owner int) (int, error) { return openParentDescriptor(path, owner, false) })
		if e != nil || !saved.Exists {
			return errors.New("original SQL/native configuration unavailable")
		}
		*target = saved.Data
	}
	if previous, e := readLegacySQLCapture(id, node); e == nil {
		if previous.ConfigSHA256 != hash || previous.WriterSHA256 != writer || !bytes.Equal(previous.NativeManifest, manifest) || !bytes.Equal(previous.NativeConfig, capture.NativeConfig) || !bytes.Equal(previous.SQLConfig, capture.SQLConfig) {
			return errors.New("original SQL capture physical evidence changed")
		}
		return nil
	} else if !errors.Is(e, os.ErrNotExist) {
		return e
	}
	cfg, e := legacySQLConnector()
	if e != nil {
		return e
	}
	connector, e := mysql.NewConnector(cfg)
	if e != nil {
		return errors.New("fixed legacy SQL connector unavailable")
	}
	if !captureOriginal {
		db := sql.OpenDB(connector)
		defer func() { _ = db.Close() }()
		if e = db.PingContext(ctx); e != nil {
			return errors.New("legacy SQL preflight unavailable; absence unproven")
		}
		return nil
	}
	capture.SQL, e = migration.SnapshotLegacySQL(ctx, connector)
	if e != nil {
		return e
	}
	after, e := nativeTreeManifest(radiusDirectory)
	if e != nil {
		return e
	}
	a, _ := json.Marshal(manifest)
	z, _ := json.Marshal(after)
	if !bytes.Equal(a, z) {
		return errors.New("native configuration changed during SQL capture")
	}
	if e = proveNativeProcessesGone(r.NativeUID); e != nil {
		return e
	}
	raw, e := json.Marshal(capture)
	if e != nil {
		return e
	}
	if e = privateWrite(filepath.Join(dir, "legacy-sql.json"), raw, 0600); e != nil {
		return e
	}
	return syncWriterDirectory(dir)
}
func readLegacySQLCapture(id, node string) (legacySQLCapture, error) {
	var c legacySQLCapture
	dir, e := writerReceiptDirectory(id)
	if e != nil {
		return c, e
	}
	raw, e := readPrivateCache(filepath.Join(dir, "legacy-sql.json"), 64<<20)
	if e != nil {
		return c, e
	}
	if domain.DecodeJSONStrict(raw, &c) != nil || c.Transition != id || c.Node != node || len(c.ConfigSHA256) != 64 || len(c.NativeManifest) == 0 || len(c.NativeConfig) == 0 || len(c.SQLConfig) == 0 {
		return c, errors.New("invalid protected original SQL capture")
	}
	writer, e := readPrivateCache(filepath.Join(dir, "receipt.json"), 16<<20)
	if e != nil || digestBytes(writer) != c.WriterSHA256 {
		return c, errors.New("original SQL writer evidence changed")
	}
	return c, nil
}
