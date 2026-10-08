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
