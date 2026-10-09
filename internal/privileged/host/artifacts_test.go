package host

import (
	"encoding/json"
	"strings"
	"testing"
)

func fixtureManifest() Manifest {
	m := Manifest{Schema: 1, Architecture: "arm64", CollectorSHA256: strings.Repeat("c", 64), PostgresCASHA256: strings.Repeat("d", 64)}
	for _, name := range requiredArtifacts {
		version := "1.0.0-1"
		if radiusPackage(name) {
			version = RadiusVersion
		}
		m.Artifacts = append(m.Artifacts, Artifact{Name: name, Version: version, Architecture: "arm64", SHA256: strings.Repeat("a", 64)})
	}
	return m
}
func TestArtifactManifestRequiresCompletePinnedFamily(t *testing.T) {
	for _, mode := range []string{"valid", "collector-checksum", "collector-version", "missing", "checksum", "traversal", "mixed", "arch", "duplicate", "unexpected"} {
		t.Run(mode, func(t *testing.T) {
			m := fixtureManifest()
			switch mode {
			case "collector-checksum":
				m.CollectorSHA256 = ""
			case "collector-version":
				m.Artifacts[len(m.Artifacts)-1].Version = "2.0.0-1"
			case "missing":
				m.Artifacts = m.Artifacts[1:]
			case "checksum":
				m.Artifacts[0].SHA256 = ""
			case "traversal":
				m.Artifacts[0].Name = "../freeradius"
			case "mixed":
				m.Artifacts[0].Version = "3.2.1"
			case "arch":
				m.Artifacts[0].Architecture = "amd64"
			case "duplicate":
				m.Artifacts = append(m.Artifacts, m.Artifacts[0])
			case "unexpected":
				m.Artifacts[0].Name = "bash"
			}
			if e := m.Validate("arm64"); (e == nil) != (mode == "valid") {
				t.Fatalf("%s: %v", mode, e)
			}
		})
	}
}

func TestManifestCannotPublishWithoutPinnedDatabaseTrust(t *testing.T) {
	m := fixtureManifest()
	data, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	if err = json.Unmarshal(data, &fields); err != nil {
		t.Fatal(err)
	}
	delete(fields, "postgres_ca_sha256")
	data, err = json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	m = Manifest{}
	if err = json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	if err = m.Validate("arm64"); err == nil {
		t.Fatal("new publication accepts an unbound PostgreSQL trust artifact")
	}
}
