package host

import (
	"strings"
	"testing"
)

func TestPackageRollbackMustMatchIndependentInstalledState(t *testing.T) {
	current := map[string]Artifact{}
	incoming := fixtureManifest()
	prior := Manifest{Schema: 1, Architecture: "arm64"}
	for _, a := range incoming.Artifacts {
		old := a
		old.Version = "0.9.0-1"
		if radiusPackage(a.Name) {
			old.Version = "3.2.1+dfsg-4"
		}
		current[a.Name] = old
		prior.Artifacts = append(prior.Artifacts, old)
	}
	if _, err := planPackages(incoming, prior, current); err != nil {
		t.Fatal(err)
	}
	prior.Artifacts[0].Version = "foreign"
	if _, err := planPackages(incoming, prior, current); err == nil {
		t.Fatal("rollback version not bound to installed state")
	}
	prior.Artifacts[0] = current[prior.Artifacts[0].Name]
	prior.Artifacts[0].SHA256 = ""
	if _, err := planPackages(incoming, prior, current); err == nil {
		t.Fatal("unchecked archive accepted")
	}
	prior.Artifacts[0].SHA256 = strings.Repeat("a", 64)
	delete(current, "freeradius-rest")
	if _, err := planPackages(incoming, prior, current); err == nil {
		t.Fatal("incomplete legacy family accepted")
	}
}

func TestRetiredUtilitiesRequireExactColdArchives(t *testing.T) {
	incoming := fixtureManifest()
	for _, a := range incoming.Artifacts {
		if a.Name == "step-cli" || a.Name == "step-kms-plugin" {
			t.Fatal("obsolete utility remains an active shipping requirement")
		}
	}
	old := Artifact{Name: "step-cli", Version: "0.30.2-1", Architecture: "arm64", SHA256: strings.Repeat("d", 64)}
	current := map[string]Artifact{old.Name: old}
	if _, err := planPackages(incoming, Manifest{}, current); err == nil {
		t.Fatal("retirement accepted without exact cold archive")
	}
	prior := Manifest{Schema: 1, Architecture: "arm64", Artifacts: []Artifact{old}}
	plan, err := planPackages(incoming, prior, current)
	if err != nil {
		t.Fatal(err)
	}
	if !plan.Changed || len(plan.Previous) != 1 || !samePackage(plan.Previous[0], old) {
		t.Fatalf("retired package not preserved: %#v", plan)
	}
	incoming.Artifacts = append(incoming.Artifacts, old)
	if incoming.Validate("arm64") == nil {
		t.Fatal("retired utility accepted for forward installation")
	}
}

func TestRetirementRefusesUnmanagedUtilityOwnership(t *testing.T) {
	old := Artifact{Name: "step-cli", Version: "0.30.2-1", Architecture: "arm64"}
	for _, tc := range []struct {
		name, owner   string
		installed, ok bool
	}{
		{"owned", "step-cli: /usr/bin/step", true, true},
		{"unmanaged", "", false, false},
		{"foreign package", "foreign: /usr/bin/step", true, false},
		{"ambiguous", "step-cli: /usr/bin/step\nforeign: /usr/bin/step", true, false},
		{"untracked installed state", "step-cli: /usr/bin/step", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			current := map[string]Artifact{}
			if tc.installed {
				current[old.Name] = old
			}
			err := validateRetiredOwner("/usr/bin/step", "step-cli", tc.owner, current)
			if (err == nil) != tc.ok {
				t.Fatalf("ownership validation: %v", err)
			}
		})
	}
}
