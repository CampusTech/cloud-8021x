package postgres

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/config"
	"github.com/jackc/pgx/v5/pgxpool"
)

func runtimeSlots(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for _, class := range []config.RuntimePool{config.PoolAccounting, config.PoolExport, config.PoolAuth, config.PoolCertificates, config.PoolObservation} {
		if err := os.WriteFile(filepath.Join(dir, string(class)+".lock"), nil, 0600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestPostgresRuntimeAggregatePoolsPreserveBothNodeReservations(t *testing.T) {
	admin, c := integration(t)
	ctx := context.Background()
	if _, err := admin.pool.Exec(ctx, "ALTER ROLE app_runtime CONNECTION LIMIT 16"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = admin.pool.Exec(context.Background(), "ALTER ROLE app_runtime CONNECTION LIMIT -1") })
	for _, managed := range []bool{false, true} {
		t.Run(map[bool]string{false: "certificates-disabled", true: "certificates-enabled"}[managed], func(t *testing.T) {
			var stores []*Store
			var held []*pgxpool.Conn
			defer func() {
				for _, conn := range held {
					conn.Release()
				}
				for _, s := range stores {
					s.Close()
				}
			}()
			dirs := []string{runtimeSlots(t), runtimeSlots(t)}
			// Fill worker allocations first; remaining independent roles must still connect.
			for _, class := range []config.RuntimePool{config.PoolAccounting, config.PoolExport, config.PoolAuth, config.PoolCertificates, config.PoolObservation} {
				if class == config.PoolCertificates && !managed {
					continue
				}
				for _, dir := range dirs {
					s, err := newRuntimeAt(ctx, roleDSN(t, "app_runtime", "disposable-runtime"), c, class, dir)
					if err != nil {
						t.Fatal(err)
					}
					stores = append(stores, s)
					limit, _ := c.RuntimePoolLimit(class)
					if s.pool.Config().MaxConns != int32(limit) {
						t.Fatal("runtime pool ignored allocation")
					}
					for range limit {
						conn, err := s.pool.Acquire(ctx)
						if err != nil {
							t.Fatalf("reserved %s capacity starved: %v", class, err)
						}
						held = append(held, conn)
					}
					bounded, cancel := context.WithTimeout(ctx, 25*time.Millisecond)
					extra, err := s.pool.Acquire(bounded)
					cancel()
					if err == nil {
						extra.Release()
						t.Fatal("pool borrowed another class allocation")
					}
					if duplicate, err := newRuntimeAt(ctx, roleDSN(t, "app_runtime", "disposable-runtime"), c, class, dir); err == nil {
						duplicate.Close()
						t.Fatal("overlapping local pool exceeded allocation")
					}
				}
			}
			var count int
			if err := admin.pool.QueryRow(ctx, "SELECT count(*) FROM pg_stat_activity WHERE usename='app_runtime'").Scan(&count); err != nil {
				t.Fatal(err)
			}
			want := 16
			if !managed {
				want = 12
			}
			if count != want {
				t.Fatalf("pair connection total %d, want %d", count, want)
			}
		})
	}
	dir := runtimeSlots(t)
	if s, err := newRuntimeAt(ctx, "invalid dsn", c, config.PoolObservation, dir); err == nil {
		s.Close()
		t.Fatal("invalid startup accepted")
	}
	s, err := newRuntimeAt(ctx, roleDSN(t, "app_runtime", "disposable-runtime"), c, config.PoolObservation, dir)
	if err != nil {
		t.Fatal("failed startup retained pool lock", err)
	}
	s.Close()
	s, err = newRuntimeAt(ctx, roleDSN(t, "app_runtime", "disposable-runtime"), c, config.PoolObservation, dir)
	if err != nil {
		t.Fatal("completed diagnostic retained slot", err)
	}
	s.Close()
}

func TestRuntimePoolLockReleasedOnProcessExit(t *testing.T) {
	if os.Getenv("C8021X_POOL_EXIT_CHILD") == "task10" {
		var c config.Database
		if json.Unmarshal([]byte(os.Getenv("C8021X_POOL_EXIT_CONFIG")), &c) != nil {
			t.Fatal("child config")
		}
		store, err := newRuntimeAt(context.Background(), "postgres://fixture:fixture@127.0.0.1:1/cloud8021x", c, config.PoolObservation, os.Getenv("C8021X_POOL_EXIT_DIRECTORY"))
		if err != nil {
			t.Fatal(err)
		}
		defer store.Close()
		fmt.Println("reserved")
		var b [1]byte
		_, _ = os.Stdin.Read(b[:])
		return
	}
	// Lazy runtime pool construction needs a valid public CA, not a database.
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, public, private)
	if err != nil {
		t.Fatal(err)
	}
	c := config.Defaults().Database
	c.CAFile = filepath.Join(t.TempDir(), "ca.pem")
	if err = os.WriteFile(c.CAFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	dir := runtimeSlots(t)
	encoded, _ := json.Marshal(c)
	cmd := exec.Command(os.Args[0], "-test.run=^TestRuntimePoolLockReleasedOnProcessExit$")
	cmd.Env = append(os.Environ(), "C8021X_POOL_EXIT_CHILD=task10", "C8021X_POOL_EXIT_CONFIG="+string(encoded), "C8021X_POOL_EXIT_DIRECTORY="+dir)
	input, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = input.Close() }()
	output, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = os.Stderr
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if cmd.ProcessState == nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	}()
	line, err := bufio.NewReader(output).ReadString('\n')
	if err != nil || line != "reserved\n" {
		t.Fatal("child did not reserve slot", line, err)
	}
	if s, e := newRuntimeAt(context.Background(), "postgres://fixture:fixture@127.0.0.1:1/cloud8021x", c, config.PoolObservation, dir); e == nil {
		s.Close()
		t.Fatal("operator overlapped existing process slot")
	}
	if err = cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = cmd.Wait()
	s, err := newRuntimeAt(context.Background(), "postgres://fixture:fixture@127.0.0.1:1/cloud8021x", c, config.PoolObservation, dir)
	if err != nil {
		t.Fatal("interrupted startup stranded allocation", err)
	}
	s.Close()
}
