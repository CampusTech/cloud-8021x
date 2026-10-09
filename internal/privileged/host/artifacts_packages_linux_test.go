package host

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/CampusTech/cloud-8021x/internal/templates/systemd"
)

func TestActualShippingClosureChild(t *testing.T) {
	if os.Getenv("C8021X_ACTUAL_CLOSURE_CHILD") != "task10" {
		t.Skip("owned package child required")
	}
	data, err := os.ReadFile(ArtifactDirectory + "/fixture-plan.json")
	if err != nil {
		t.Fatal(err)
	}
	var plan PackagePlan
	if err = json.Unmarshal(data, &plan); err != nil {
		t.Fatal(err)
	}
	if err = plan.install(context.Background()); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("/opt/datadog-agent/embedded/bin/python", "/native-probe.py").CombinedOutput(); err != nil {
		t.Fatalf("actual native package acceptance: %s %v", out, err)
	} else {
		t.Log(string(out))
	}
	units, err := systemd.Render()
	if err != nil {
		t.Fatal(err)
	}
	for path, contents := range units {
		if err = os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(path, contents, 0644); err != nil {
			t.Fatal(err)
		}
	}
	for _, file := range ParallelPassiveFiles() {
		if err = os.MkdirAll(filepath.Dir(file.Path), 0755); err != nil {
			t.Fatal(err)
		}
		if err = Write(file); err != nil {
			t.Fatal(err)
		}
	}
	args := []string{"--man=no", "verify", "cloud-8021x.service", "freeradius.service", "step-ca.service", "step-ca-rsa.service", "datadog-agent.service", "datadog-agent-ddot.service"}
	if out, err := exec.Command("/usr/bin/systemd-analyze", args...).CombinedOutput(); err != nil {
		t.Fatalf("actual systemd unit/parallel barrier verification: %s %v", out, err)
	}
	condition := "ConditionPathExists=" + ParallelActiveFile
	if err = exec.Command("/usr/bin/systemd-analyze", "condition", condition).Run(); err == nil {
		t.Fatal("passive condition passed without activation marker")
	}
	if err = os.MkdirAll(filepath.Dir(ParallelActiveFile), 0700); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(ParallelActiveFile, []byte("fixture-only"), 0600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("/usr/bin/systemd-analyze", "condition", condition).CombinedOutput(); err != nil {
		t.Fatalf("actual positive systemd condition: %s %v", out, err)
	}
	if err = os.Remove(ParallelActiveFile); err != nil {
		t.Fatal(err)
	}
	t.Log("PASS actual systemd unit syntax and negative/positive parallel marker condition; no PID1/start/reboot claim")
	// Exit the original helper after installation, without running its cleanup.
	// The parent must recover solely from the persisted immutable package plan.
	os.Exit(73)
}

func TestActualShippingClosureInstallAndInterruptedRollback(t *testing.T) {
	if os.Getenv("C8021X_ACTUAL_CLOSURE") != "task10" {
		t.Skip("owned networkless Debian13 package fixture required")
	}
	ctx := context.Background()
	data, err := os.ReadFile("/bundle/package-manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	var manifest Manifest
	if err = json.Unmarshal(data, &manifest); err != nil {
		t.Fatal(err)
	}
	// This fixture exercises package publication, not database publication.
	manifest.PostgresCASHA256 = strings.Repeat("d", 64)
	if err = manifest.Validate(manifest.Architecture); err != nil {
		t.Fatal(err)
	}
	if err = os.MkdirAll(ArtifactDirectory, 0700); err != nil {
		t.Fatal(err)
	}
	for _, artifact := range manifest.Artifacts {
		data, err = os.ReadFile(filepath.Join("/bundle", artifact.filename()))
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(filepath.Join(ArtifactDirectory, artifact.filename()), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err = VerifyArtifacts(ctx, manifest); err != nil {
		t.Fatal(err)
	}
	bad := manifest
	bad.Artifacts = append([]Artifact(nil), manifest.Artifacts...)
	bad.Artifacts[0].SHA256 = strings.Repeat("0", 64)
	if err = VerifyArtifacts(ctx, bad); err == nil {
		t.Fatal("tampered authenticated package accepted")
	}
	incomplete := manifest
	incomplete.Artifacts = nil
	for _, artifact := range manifest.Artifacts {
		if artifact.Name != "libtalloc2" {
			incomplete.Artifacts = append(incomplete.Artifacts, artifact)
		}
	}
	if _, err = PreparePackages(ctx, incomplete); err == nil {
		t.Fatal("missing actual native dependency accepted")
	}
	plan, err := PreparePackages(ctx, manifest)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Previous) != 0 || len(plan.Absent) == 0 || !plan.Changed {
		t.Fatalf("unexpected clean-image package plan: %#v", plan)
	}
	before, err := readPackageInventory()
	if err != nil {
		t.Fatal(err)
	}
	checkpoint, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	if err = privateWrite(ArtifactDirectory+"/fixture-plan.json", checkpoint, 0600); err != nil {
		t.Fatal(err)
	}
	child := exec.Command(os.Args[0], "-test.run", "^TestActualShippingClosureChild$", "-test.v")
	child.Env = append(os.Environ(), "C8021X_ACTUAL_CLOSURE_CHILD=task10")
	out, err := child.CombinedOutput()
	t.Log(string(out))
	var exited *exec.ExitError
	if !errors.As(err, &exited) || exited.ExitCode() != 73 {
		t.Fatalf("actual installed child did not reach interrupted boundary: %v", err)
	}
	var recovered PackagePlan
	checkpoint, err = os.ReadFile(ArtifactDirectory + "/fixture-plan.json")
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(checkpoint, &recovered); err != nil {
		t.Fatal(err)
	}
	if err = recovered.Rollback(ctx); err != nil {
		diagnostic, diagnosticErr := exec.Command("/usr/bin/dpkg", "--audit").CombinedOutput()
		t.Logf("owned fixture read-only package audit: %s %v", diagnostic, diagnosticErr)
		t.Fatal(err)
	}
	after, err := readPackageInventory()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, after) {
		t.Fatal("base package inventory changed after exact interrupted rollback")
	}
}
