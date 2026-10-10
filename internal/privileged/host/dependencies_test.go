package host

import (
	"strings"
	"testing"
)

func TestDebianBinaryRelationshipSyntax(t *testing.T) {
	for _, value := range []string{"debconf (>= 0.5) | debconf-2.0, debconf (>= 1.5.19) | cdebconf, libpam-modules (>= 1.0.1-6)", "libpam-modules (<< 1.7.0), libpam-modules-bin (<< 1.7.0)", "libc6:any (>= 2:2.38-1)", "virtual-abi (= 1.2~rc1+campus1)"} {
		if _, err := parseRelations(value); err != nil {
			t.Fatalf("%s: %v", value, err)
		}
	}
	for _, value := range []string{"libc6 [amd64]", "libc6 (>=)", "libc6 || libssl3t64", "libc6; touch /tmp/unmanaged"} {
		if _, err := parseRelations(value); err == nil {
			t.Fatal("unsupported relationship accepted", value)
		}
	}
}

func TestDependencyInventoryChecksAlternativesVersionsConflictsAndReverseDependencies(t *testing.T) {
	compare := func(a, op, b string) bool {
		switch op {
		case "=":
			return a == b
		case ">=":
			return a >= b
		case "<<":
			return a < b
		}
		return false
	}
	app := debPackage{Artifact: Artifact{Name: "step-ca", Version: "1", Architecture: "arm64"}, Depends: "virtual-signer (>= 2) | fallback-signer"}
	signer := debPackage{Artifact: Artifact{Name: "local-signer", Version: "3", Architecture: "all"}, Provides: "virtual-signer (= 2)"}
	for _, mode := range []string{"valid", "missing", "old provider", "conflict", "reverse", "unsupported"} {
		t.Run(mode, func(t *testing.T) {
			packages := map[string]debPackage{app.Name: app, signer.Name: signer}
			switch mode {
			case "missing":
				delete(packages, signer.Name)
			case "old provider":
				p := signer
				p.Provides = "virtual-signer (= 1)"
				packages[p.Name] = p
			case "conflict":
				p := app
				p.Conflicts = "local-signer"
				packages[p.Name] = p
			case "reverse":
				p := signer
				p.Depends = "retired-utility"
				packages[p.Name] = p
			case "unsupported":
				p := app
				p.Depends = "libc6 [amd64]"
				packages[p.Name] = p
			}
			if err := checkDependencies(packages, "arm64", compare); (err == nil) != (mode == "valid") {
				t.Fatalf("dependency check: %v", err)
			}
		})
	}
}

func TestDependencyManifestAndUnchangedNewerInstalledPackage(t *testing.T) {
	incoming := fixtureManifest()
	dependency := Artifact{Name: "libpq5", Version: "17.5-1", Architecture: "arm64", SHA256: strings.Repeat("a", 64)}
	incoming.Artifacts = append(incoming.Artifacts, dependency)
	if err := incoming.Validate("arm64"); err != nil {
		t.Fatal(err)
	}
	old := dependency
	old.Version = "17.6-1"
	plan, err := planPackages(incoming, Manifest{}, map[string]Artifact{old.Name: old}, func(a, op, b string) bool { return op == ">=" && a >= b })
	if err != nil {
		t.Fatal(err)
	}
	if !samePackage(plan.Retained[old.Name], old) || len(plan.Previous) != 0 {
		t.Fatal("satisfied newer dependency would be downgraded")
	}
	if _, err = planPackages(incoming, Manifest{}, map[string]Artifact{old.Name: old}, func(string, string, string) bool { return false }); err == nil {
		t.Fatal("changed dependency without exact prior archive accepted")
	}
	incoming.Artifacts[len(incoming.Artifacts)-1].Name = "libc6"
	if incoming.Validate("arm64") == nil {
		t.Fatal("OS-critical archive accepted")
	}
	incoming = fixtureManifest()
	incoming.Artifacts = incoming.Artifacts[1:]
	incoming.Artifacts = append(incoming.Artifacts, dependency)
	if incoming.Validate("arm64") == nil {
		t.Fatal("dependency substituted for missing product")
	}
}

func TestExistingProtectedBaseHelperRequiresSeparatePreparation(t *testing.T) {
	incoming := fixtureManifest()
	a := Artifact{Name: "openssl", Version: "3.5.6-1", Architecture: "arm64", SHA256: strings.Repeat("a", 64)}
	incoming.Artifacts = append(incoming.Artifacts, a)
	old := a
	old.Version = "3.5.1-1"
	prior := Manifest{Schema: 1, Architecture: "arm64", Artifacts: []Artifact{old}}
	if _, err := planPackages(incoming, prior, map[string]Artifact{old.Name: old}, func(string, string, string) bool { return false }); err == nil {
		t.Fatal("base helper upgraded through application package transition")
	}
	if _, err := planPackages(incoming, Manifest{}, map[string]Artifact{}, nil); err != nil {
		t.Fatal("new helper install refused", err)
	}
}
