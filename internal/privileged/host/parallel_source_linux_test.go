package host

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/adoption"
	"github.com/CampusTech/cloud-8021x/internal/config"
)

func TestInstalledParallelSourceCaptureRetainsAuthorizationOnly(t *testing.T) {
	if os.Getenv("C8021X_PARALLEL_RUNTIME_FIXTURE") != "task10" {
		t.Skip("owned disposable task10 Linux source fixture required")
	}
	if out, err := exec.Command("/usr/sbin/useradd", "--system", "--uid", "1001", "freerad").CombinedOutput(); err != nil {
		t.Fatalf("fixture native account: %v %s", err, out)
	}
	write := func(path string, data []byte, mode os.FileMode) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, data, mode); err != nil {
			t.Fatal(err)
		}
	}
	for _, path := range append(append([]string{}, legacyWriterCrons...), writerUnitPaths(legacyWriterUnits)...) {
		data := []byte("# original scheduler\n")
		if strings.HasSuffix(path, "radius-usage-collector.service") {
			data = []byte("# Managed radius usage monitor; does not control FreeRADIUS.\n")
		}
		write(path, data, 0644)
	}
	write(legacyVLANModule, []byte("import sys\ndef cached_name():\n    return 'fixture'\n\nif __name__ == '__main__':\n    sys.exit(main())\n"), 0644)
	policy := []byte(`{"version":2,"updated_at":1791453600,"identities":{"opaque-device":{"device_id":"opaque-device","groups":[],"enrolled":true}},"certificates":{"` + strings.Repeat("a", 64) + `":{"device_id":"opaque-device","groups":[],"enrolled":true,"observed_at":1791453500}},"hardware_serials":{}}`)
	write(legacyStatePaths["policy"], policy, 0644)
	certificates := []byte(`{"version":1,"source":"https://fleet.example.test","trust":null,"hosts":{},"commands":[]}`)
	write(legacyStatePaths["certificates"], certificates, 0600)
	write("/run/radius-accounting-key", []byte(strings.Repeat("k", 32)), 0600)
	write(legacyDowngradeGuard, []byte(""), 0600)
	write("/etc/freeradius/3.0/radiusd.conf", []byte("source native remains intact"), 0644)
	for _, path := range []string{"/etc/step-ca/certs/intermediate_ca.crt", "/etc/step-ca/certs/root_ca.crt", "/etc/step-ca-rsa/certs/intermediate_ca.crt", "/etc/step-ca-rsa/certs/root_ca.crt", "/etc/acme-authz-webhook/server.crt", "/etc/acme-authz-webhook/server.key", "/etc/step-ca/config/ca.json", "/etc/step-ca-rsa/config/ca.json", "/etc/step-ca/templates/x509/wifi-acme.tpl", "/etc/step-ca-rsa/templates/x509/wifi-scep.tpl"} {
		write(path, []byte("original protected native identity"), 0600)
	}
	// Poison history proves this protocol never invokes the accounting decoder.
	write(legacyStatePaths["usage"], []byte("historical accounting is not imported"), 0600)
	pin, err := ParallelSourceKey()
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Defaults()
	cfg.InstanceID = "radius-primary"
	cfg.StateTransition = strings.Repeat("c", 64)
	cfg.Database.Name = "cloud8021x_green"
	cfg.Deployment = config.Deployment{Mode: "parallel", ID: "green", Instance: "green-primary", SourceID: "blue", SourcePrimary: "radius-primary", SourceSecondary: "radius-secondary", SourcePrimaryKey: pin, SourceSecondaryKey: strings.Repeat("f", 64), CollectionEpoch: time.Now().UTC().Truncate(time.Second)}
	green1, key1, _ := ed25519.GenerateKey(rand.Reader)
	green2, key2, _ := ed25519.GenerateKey(rand.Reader)
	cfg.Deployment.DestinationPrimaryKey = hex.EncodeToString(green1)
	cfg.Deployment.DestinationSecondaryKey = hex.EncodeToString(green2)
	calls := []string{}
	run := func(_ context.Context, path string, args ...string) ([]byte, error) {
		calls = append(calls, path+" "+strings.Join(args, " "))
		return []byte("ActiveState=inactive\nSubState=dead\nMainPID=0\n"), nil
	}
	raw, err := captureParallelSource(context.Background(), cfg, strings.Repeat("d", 64), run)
	if err != nil {
		t.Fatal(err)
	}
	document, err := VerifyParallelSource(raw, cfg, strings.Repeat("d", 64), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(document.Policy, policy) || !bytes.Equal(document.Certificates, certificates) || !document.FingerprintEnforced {
		t.Fatal("original policy or timestamps changed")
	}
	for _, call := range calls {
		if strings.Contains(call, "stop freeradius") || strings.Contains(call, "stop step-ca") {
			t.Fatal("source capture stopped native authentication or CA")
		}
	}
	var decoded map[string]any
	if json.Unmarshal(raw, &decoded) != nil {
		t.Fatal("invalid signed envelope")
	}
	if bytes.Contains(raw, []byte("historical accounting")) {
		t.Fatal("accounting history entered authorization transfer")
	}
	if err = os.Remove(legacyStatePaths["certificates"]); err != nil {
		t.Fatal(err)
	}
	if _, err = captureParallelSource(context.Background(), cfg, strings.Repeat("d", 64), run); err == nil {
		t.Fatal("missing command provenance accepted")
	}
	cfg.Deployment.SourcePrimary = "radius-primary"
	if err = resumeParallelSource(context.Background(), cfg, strings.Repeat("d", 64), run); err == nil {
		t.Fatal("missing green proofs resumed old schedulers")
	}
	manifest, _ := cfg.ParallelManifest()
	for i, role := range []string{"radius-primary", "radius-secondary"} {
		key := key1
		if i == 1 {
			key = key2
		}
		receipt := adoption.Rollback{ReleaseSHA256: strings.Repeat("d", 64), ManifestSHA256: manifest, Transition: cfg.StateTransition, Deployment: "green", SourceDeployment: "blue", Role: role, Instance: "green" + strings.TrimPrefix(role, "radius"), FenceSHA256: strings.Repeat("f", 64), ObservedAt: time.Now().UTC(), CommandsReconciled: true}
		raw, e := adoption.SignRollback(receipt, key)
		if e != nil {
			t.Fatal(e)
		}
		write(ArtifactDirectory+"/rollback-"+role+".json", raw, 0600)
		if i == 0 && resumeParallelSource(context.Background(), cfg, strings.Repeat("d", 64), run) == nil {
			t.Fatal("single physical green fence resumed source")
		}
	}
	if err = resumeParallelSource(context.Background(), cfg, strings.Repeat("d", 64), run); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(legacyWriterCrons[0])
	if err != nil || !bytes.Contains(data, []byte("original scheduler")) {
		t.Fatal("original source scheduler not restored", err)
	}
	cfg.Deployment.SourcePrimary = "other-source"
	if _, err = captureParallelSource(context.Background(), cfg, strings.Repeat("d", 64), run); err == nil {
		t.Fatal("green disk fabricated old physical source")
	}
	cfg.Deployment.SourcePrimary = "radius-primary"
	if err = BeginParallelPrepare(cfg, strings.Repeat("d", 64)); err != nil {
		t.Fatal(err)
	}
	if _, _, err = recoverParallelPrepare(context.Background(), cfg, strings.Repeat("d", 64), "", run); err == nil {
		t.Fatal("live preparation helper was recovered")
	}
	child := exec.Command("/bin/sleep", "30")
	if err = child.Start(); err != nil {
		t.Fatal(err)
	}
	processes, err := scanWriterProcesses()
	if err != nil {
		t.Fatal(err)
	}
	var original writerPID
	for _, p := range processes {
		if p.PID == child.Process.Pid {
			original = writerPID{p.PID, p.Start}
		}
	}
	if original.Start == 0 {
		t.Fatal("child PID start unavailable")
	}
	if err = child.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = child.Wait()
	binding, _ := adoption.ExpectedBinding(cfg, strings.Repeat("d", 64))
	proof, _ := json.Marshal(parallelPrepareHelper{ConfigSHA256: binding.ConfigSHA256, ReleaseSHA256: strings.Repeat("d", 64), Helper: original})
	if err = Write(File{Path: parallelPrepareFile, Data: proof, Mode: 0600}); err != nil {
		t.Fatal(err)
	}
	if _, _, err = recoverParallelPrepare(context.Background(), cfg, strings.Repeat("d", 64), "", run); err != nil {
		t.Fatal(err)
	}
	for _, barrier := range ParallelPassiveFiles() {
		data, e := os.ReadFile(barrier.Path)
		if e != nil || !bytes.Equal(data, barrier.Data) {
			t.Fatal("passive recovery lost durable unit condition", e)
		}
	}
	changed := cfg
	changed.Deployment.SourceID = "other-blue"
	if _, _, err = recoverParallelPrepare(context.Background(), changed, strings.Repeat("d", 64), "", run); err == nil {
		t.Fatal("different source/config recovered preparation")
	}

}
