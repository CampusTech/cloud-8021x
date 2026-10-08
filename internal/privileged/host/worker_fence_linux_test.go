package host

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/templates/systemd"
)

func TestInstalledWorkerProcessChild(t *testing.T) {
	if os.Getenv("C8021X_WORKER_PROCESS") != "task9" {
		t.Skip("fixture child")
	}
	time.Sleep(time.Hour)
}
func TestInstalledWorkerFenceChild(t *testing.T) {
	if os.Getenv("C8021X_WORKER_FENCE_CHILD") != "task9" {
		t.Skip("fixture child")
	}
	pid, _ := strconv.Atoi(os.Getenv("C8021X_WORKER_PID"))
	b := &RadiusBackend{run: func(_ context.Context, _ string, args ...string) ([]byte, error) {
		if len(args) > 1 && args[0] == "stop" && args[1] == "cloud-8021x.service" {
			_ = syscall.Kill(pid, syscall.SIGKILL)
			return nil, errors.New("fixture interruption immediately after daemon stop")
		}
		return []byte("ActiveState=inactive\nSubState=dead\nMainPID=0\n"), nil
	}}
	_, e := FenceDaemonWorkers(context.Background(), strings.Repeat("d", 64), "radius-primary", strings.Repeat("e", 64), b, 99, false)
	if e == nil {
		t.Fatal("fixture did not interrupt")
	}
}
func TestInstalledWorkerFenceInterruptedProcessAndUnitProof(t *testing.T) {
	if os.Getenv("C8021X_WRITER_FIXTURE") != "task9" {
		t.Skip("owned Linux worker fixture")
	}
	if _, _, e := identity("freerad"); e != nil {
		if out, e := exec.Command("/usr/sbin/useradd", "--system", "--uid", "1001", "freerad").CombinedOutput(); e != nil {
			t.Fatal(e, string(out))
		}
	}
	units, e := systemd.Render()
	if e != nil {
		t.Fatal(e)
	}
	for _, unit := range daemonWorkerUnits {
		path := "/etc/systemd/system/" + unit
		_ = os.Remove(path)
		_ = os.Remove(filepath.Join(filepath.Dir(path), ".cloud8021x-mask-"+unit))
		if e = os.MkdirAll(filepath.Dir(path), 0755); e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(path, units[path], 0644); e != nil {
			t.Fatal(e)
		}
	}
	module := radiusDirectory + "/mods-enabled/auth_detail"
	if e = os.MkdirAll(filepath.Dir(module), 0755); e != nil {
		t.Fatal(e)
	}
	originalModule := []byte(" filename = \"/var/log/freeradius/auth/auth-" + strings.Repeat("a", 32) + "-%Y%m%d%H.detail\"\n")
	if e = os.WriteFile(module, originalModule, 0644); e != nil {
		t.Fatal(e)
	}
	start := func() *exec.Cmd {
		t.Helper()
		cmd := exec.Command(os.Args[0], "-test.run=^TestInstalledWorkerProcessChild$")
		cmd.Args[0] = "/usr/local/bin/cloud-8021x"
		cmd.Env = append(os.Environ(), "C8021X_WORKER_PROCESS=task9")
		if e := cmd.Start(); e != nil {
			t.Fatal(e)
		}
		return cmd
	}
	daemon := start()
	defer func() { _ = daemon.Process.Kill(); _ = daemon.Wait() }()
	child := exec.Command(os.Args[0], "-test.run=^TestInstalledWorkerFenceChild$")
	child.Env = append(os.Environ(), "C8021X_WORKER_FENCE_CHILD=task9", "C8021X_WORKER_PID="+strconv.Itoa(daemon.Process.Pid))
	if out, e := child.CombinedOutput(); e != nil {
		t.Fatalf("fence child: %v %s", e, out)
	}
	_ = daemon.Wait()
	id, hash := strings.Repeat("d", 64), strings.Repeat("e", 64)
	_, original, e := loadWorkerFence(id, "radius-primary", hash, 99)
	if e != nil {
		t.Fatal(e)
	}
	mutations := 0
	b := &RadiusBackend{run: func(_ context.Context, _ string, args ...string) ([]byte, error) {
		if len(args) > 0 && args[0] != "show" {
			mutations++
		}
		return []byte("ActiveState=inactive\nSubState=dead\nMainPID=0\n"), nil
	}}
	changed := "/etc/systemd/system/cloud-8021x-renew.timer"
	if e = os.Remove(changed); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(changed, []byte("foreign unit"), 0644); e != nil {
		t.Fatal(e)
	}
	if _, e = FenceDaemonWorkers(context.Background(), id, "radius-primary", hash, b, 99, true); e == nil || mutations != 0 {
		t.Fatal("foreign partial unit permitted writes", e, mutations)
	}
	if e = os.Remove(changed); e != nil {
		t.Fatal(e)
	}
	if e = os.Symlink("/dev/null", changed); e != nil {
		t.Fatal(e)
	}
	replacement := start()
	if _, e = FenceDaemonWorkers(context.Background(), id, "radius-primary", hash, b, 99, true); e == nil || mutations != 0 {
		t.Fatal("restarted Go worker permitted recovery", e)
	}
	_ = replacement.Process.Kill()
	_ = replacement.Wait()
	if e = os.WriteFile(module, bytes.Replace(originalModule, []byte(strings.Repeat("a", 32)), []byte(strings.Repeat("b", 32)), 1), 0644); e != nil {
		t.Fatal(e)
	}
	if _, e = FenceDaemonWorkers(context.Background(), id, "radius-primary", hash, b, 99, true); e == nil || mutations != 0 {
		t.Fatal("changed native generation permitted recovery", e)
	}
	if e = os.WriteFile(module, originalModule, 0644); e != nil {
		t.Fatal(e)
	}
	receipt, e := FenceDaemonWorkers(context.Background(), id, "radius-primary", hash, b, 99, true)
	if e != nil || receipt != digestBytes(original) {
		t.Fatal("exact worker fence continuation", e)
	}
	_, retained, e := loadWorkerFence(id, "radius-primary", hash, 99)
	if e != nil || !bytes.Equal(retained, original) {
		t.Fatal("worker original receipt changed", e)
	}
	if _, e = VerifyDaemonWorkerFence(context.Background(), id, "radius-primary", hash, b); e != nil {
		t.Fatal(e)
	}
}
