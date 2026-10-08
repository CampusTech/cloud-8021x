package host

import (
	"bytes"
	"context"
	"database/sql"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"github.com/go-sql-driver/mysql"
)

func TestInstalledLegacySQLCaptureOriginalReadOnly(t *testing.T) {
	if os.Getenv("C8021X_SQL_FIXTURE") != "task9" {
		t.Skip("owned MariaDB fixture")
	}
	ctx := context.Background()
	if out, e := exec.Command("/usr/sbin/useradd", "--system", "--uid", "1001", "freerad").CombinedOutput(); e != nil {
		t.Fatal(e, string(out))
	}
	for path, data := range map[string][]byte{legacyVLANModule: []byte("import sys\nif __name__ == '__main__':\n    sys.exit(main())\n"), radiusDirectory + "/radiusd.conf": []byte("original native SQL configuration"), radiusDirectory + "/mods-available/sql": []byte("driver = rlm_sql_mysql\nserver = localhost\n"), legacyPolicySnapshot: []byte(`{"version":2,"updated_at":1791453600.123456789,"identities":{},"certificates":{},"hardware_serials":{}}`), "/run/radius-accounting-key": bytes.Repeat([]byte("k"), 32)} {
		if e := os.MkdirAll(filepath.Dir(path), 0755); e != nil {
			t.Fatal(e)
		}
		if e := os.WriteFile(path, data, 0600); e != nil {
			t.Fatal(e)
		}
	}
	if e := os.Chown("/run/radius-accounting-key", 1001, 1001); e != nil {
		t.Fatal(e)
	}
	stopped := func(context.Context, string, ...string) ([]byte, error) {
		return []byte("ActiveState=inactive\nSubState=dead\nMainPID=0\n"), nil
	}
	id, hash := strings.Repeat("8", 64), strings.Repeat("7", 64)
	unlock, e := AcquireWriterOperation()
	if e != nil {
		t.Fatal(e)
	}
	defer unlock()
	writer, e := fenceLegacyWriters(ctx, id, "radius-primary", hash, stopped, legacyProcessesQuiescent)
	if e != nil {
		t.Fatal(e)
	}
	active := &RadiusBackend{run: func(_ context.Context, _ string, args ...string) ([]byte, error) {
		if len(args) > 1 && args[1] == "freeradius.service" {
			return []byte("ActiveState=active\nSubState=running\nMainPID=42\n"), nil
		}
		return stopped(ctx, "")
	}}
	if e = captureLegacySQL(ctx, id, "radius-primary", hash, writer, active); e == nil {
		t.Fatal("active native SQL producer accepted")
	}
	child := exec.Command("/bin/sleep", "60")
	child.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 1001, Gid: 1001}}
	if e = child.Start(); e != nil {
		t.Fatal(e)
	}
	e = captureLegacySQL(ctx, id, "radius-primary", hash, writer, &RadiusBackend{run: stopped})
	_ = child.Process.Kill()
	_ = child.Wait()
	if e == nil {
		t.Fatal("living native UID accepted")
	}
	if e = captureLegacySQL(ctx, id, "radius-primary", hash, writer, &RadiusBackend{run: stopped}); e != nil {
		cfg, ce := legacySQLConnector()
		if ce != nil {
			t.Fatal(e, ce)
		}
		c, ce := mysql.NewConnector(cfg)
		if ce != nil {
			t.Fatal(e, ce)
		}
		db := sql.OpenDB(c)
		defer func() { _ = db.Close() }()
		t.Fatal(e, db.PingContext(ctx))
	}
	saved, e := readLegacySQLCapture(id, "radius-primary")
	if e != nil {
		t.Fatal(e)
	}
	if len(saved.SQL.Rows) != 2 || *saved.SQL.Rows[0].Input != math.MaxUint64 || *saved.SQL.Rows[0].Start != "2026-10-08 12:34:56.123456" || saved.SQL.Rows[1].Stop != nil || saved.SQL.Rows[1].Input != nil {
		t.Fatal("SQL original evidence changed", saved.SQL)
	}
	dir, _ := writerReceiptDirectory(id)
	original, e := os.ReadFile(filepath.Join(dir, "legacy-sql.json"))
	if e != nil {
		t.Fatal(e)
	}
	if e = captureLegacySQL(ctx, id, "radius-primary", hash, writer, &RadiusBackend{run: stopped}); e != nil {
		t.Fatal(e)
	}
	again, _ := os.ReadFile(filepath.Join(dir, "legacy-sql.json"))
	if !bytes.Equal(original, again) {
		t.Fatal("SQL archive rewritten")
	}
	if _, e = CaptureLegacyState(id, "radius-primary", bytes.Repeat([]byte("k"), 32)); e != nil {
		t.Fatal("full original bundle", e)
	}
	// A missing or substituted socket never becomes an empty database.
	if e = os.Rename(legacySQLSocket, legacySQLSocket+".fixture"); e != nil {
		t.Fatal(e)
	}
	defer func() { _ = os.Remove(legacySQLSocket); _ = os.Rename(legacySQLSocket+".fixture", legacySQLSocket) }()
	cfg, e := legacySQLConnector()
	if e != nil {
		t.Fatal(e)
	}
	if _, e = cfg.DialFunc(ctx, "unix", legacySQLSocket); e == nil {
		t.Fatal("missing socket accepted")
	}
	if e = os.Symlink(legacySQLSocket+".fixture", legacySQLSocket); e != nil {
		t.Fatal(e)
	}
	if _, e = cfg.DialFunc(ctx, "unix", legacySQLSocket); e == nil {
		t.Fatal("socket symlink accepted")
	}
}

func TestInstalledLegacySQLCapturePreparationBoundaries(t *testing.T) {
	if os.Getenv("C8021X_SQL_FIXTURE") != "task9" {
		t.Skip("owned MariaDB fixture")
	}
	ctx := context.Background()
	node, hash := "radius-primary", strings.Repeat("7", 64)
	class := bytes.Repeat([]byte("k"), 32)
	stopped := func(context.Context, string, ...string) ([]byte, error) {
		return []byte("ActiveState=inactive\nSubState=dead\nMainPID=0\n"), nil
	}
	if stage := os.Getenv("C8021X_CAPTURE_STAGE"); stage != "" {
		id := os.Getenv("C8021X_CAPTURE_ID")
		dir, _ := writerReceiptDirectory(id)
		receipt, e := readPrivateCache(filepath.Join(dir, "receipt.json"), 16<<20)
		if e != nil {
			t.Fatal(e)
		}
		writer := digestBytes(receipt)
		release, e := AcquireWriterOperation()
		if e != nil {
			t.Fatal(e)
		}
		defer release()
		if e = PrepareLegacyCaptureAttempt(id, node, hash, writer, 77); e != nil {
			t.Fatal(e)
		}
		if e = ProveLegacyCaptureStopped(id, node, hash, writer, 77); e == nil {
			t.Fatal("live helper accepted")
		}
		if stage == "prepared" {
			return
		}
		if e = captureLegacySQL(ctx, id, node, hash, writer, &RadiusBackend{run: stopped}); e != nil {
			t.Fatal(e)
		}
		if stage == "sql" {
			return
		}
		if _, e = CaptureLegacyState(id, node, class); e != nil {
			t.Fatal(e)
		}
		if stage == "bundle" {
			return
		}
		if e = CompleteLegacyCapture(id, node, hash, writer, 77, class); e != nil {
			t.Fatal(e)
		}
		return
	}
	for i, stage := range []string{"prepared", "sql", "bundle", "complete"} {
		t.Run(stage, func(t *testing.T) {
			id := strings.Repeat(strconv.Itoa(i+1), 64)
			if e := os.WriteFile(legacyVLANModule, []byte("import sys\nif __name__ == '__main__':\n    sys.exit(main())\n"), 0600); e != nil {
				t.Fatal(e)
			}
			writer, e := fenceLegacyWriters(ctx, id, node, hash, stopped, legacyProcessesQuiescent)
			if e != nil {
				t.Fatal(e)
			}
			child := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestInstalledLegacySQLCapturePreparationBoundaries$")
			child.Env = append(os.Environ(), "C8021X_CAPTURE_STAGE="+stage, "C8021X_CAPTURE_ID="+id)
			if out, e := child.CombinedOutput(); e != nil {
				t.Fatal(e, string(out))
			}
			release, e := AcquireWriterOperation()
			if e != nil {
				t.Fatal(e)
			}
			defer release()
			if original, e := LegacyCaptureOriginalAttempt(id, node, hash, writer); e != nil || original != 77 {
				t.Fatal("original bounded attempt lookup", original, e)
			}
			if e = ProveLegacyCaptureStopped(id, node, hash, writer, 77); e != nil {
				t.Fatal(e)
			}
			if e = ProveLegacyCaptureStopped(id, node, hash, writer, 78); e == nil {
				t.Fatal("foreign original accepted")
			}
			complete, e := LegacyCaptureRecorded(id, node, hash, writer, 77, class)
			if stage == "sql" {
				if e == nil {
					t.Fatal("partial SQL archive treated as full capture")
				}
				return
			}
			if e != nil || complete != (stage != "prepared") {
				t.Fatal(complete, e)
			}
			if stage == "prepared" {
				return
			}
			if e = inspectLegacySQL(ctx, id, node, hash, writer, &RadiusBackend{run: stopped}, false); e != nil {
				t.Fatal("saved physical proof", e)
			}
			path := radiusDirectory + "/mods-available/sql"
			old, e := os.ReadFile(path)
			if e != nil {
				t.Fatal(e)
			}
			if e = os.WriteFile(path, []byte("foreign replacement"), 0600); e != nil {
				t.Fatal(e)
			}
			if e = inspectLegacySQL(ctx, id, node, hash, writer, &RadiusBackend{run: stopped}, false); e == nil {
				t.Fatal("changed native SQL accepted")
			}
			if e = os.WriteFile(path, old, 0600); e != nil {
				t.Fatal(e)
			}
		})
	}
}
