package main

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/config"
	"github.com/CampusTech/cloud-8021x/internal/privileged/host"
	seed "github.com/CampusTech/cloud-8021x/tests/runtime/task11-assembly-seed/contract"
)

func assemblyInputs(t *testing.T) (plan, seed.Input, map[string][]byte, host.Manifest) {
	t.Helper()
	s, files := nativeInputs(t)
	s.ObservedAt = s.CollectionEpoch.Add(-time.Hour)
	s.APICA = seed.FilePin{Path: "api/ca.pem", SHA256: digest([]byte("synthetic API CA"))}
	files[s.APICA.Path] = []byte("synthetic API CA")
	for _, n := range []string{"postgres/server.pem", "postgres/server.key", "postgres/init.sql", "postgres/pg_hba.conf", "postgres/postgresql.conf", "api/tls.pem", "api/tls.key"} {
		files[n] = []byte("synthetic-only unit fixture " + n)
	}
	original := struct {
		Schema int
		Files  map[string]string
	}{1, map[string]string{}}
	for _, n := range originalNames {
		original.Files[n] = digest(files[n])
	}
	raw, err := json.Marshal(original)
	if err != nil {
		t.Fatal(err)
	}
	files["original-manifest.json"] = raw
	s.OriginalManifestSHA256 = digest(raw)
	s.OriginalStateSHA256 = digest(files["source/var/lib/cloud-8021x/certificate-state.json"])
	s.InstalledSeedSHA256 = digest(files["api/seed.json"])
	s.Files = map[string]string{}
	for n, b := range files {
		s.Files[n] = digest(b)
	}
	pin := strings.Repeat("a", 64)
	p := plan{Schema: 1, InputSHA256: pin, ManifestSHA256: pin, Application: binaryPin{"/private/app", pin}, Controller: binaryPin{"/private/controller", pin}, Observer: binaryPin{"/private/observer", pin}, Cloud: binaryPin{"/private/cloud", pin}, ApplicationSourceSHA: strings.Repeat("a", 40), ObserverSourceSHA256: pin, CloudSourceSHA256: pin, PrimitiveSeedSHA256: pin, PrimitiveExpectedSHA256: pin, Transition: pin, MachineIDs: map[string]string{}}
	for i, n := range []string{"blue-primary", "blue-secondary", "green-primary", "green-secondary"} {
		p.MachineIDs[n] = strings.Repeat(string(rune('a'+i)), 32)
	}
	raw, err = os.ReadFile("testdata/package-manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	var m host.Manifest
	if err = json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	m.PostgresCASHA256 = s.PostgresCA.SHA256
	return p, s, files, m
}
func TestFourRoleCandidateBindingsAndNoFabricatedReceipts(t *testing.T) {
	p, s, files, m := assemblyInputs(t)
	o, err := assemble(p, s, files, m)
	if err != nil {
		t.Fatal(err)
	}
	for _, role := range []string{"primary", "secondary"} {
		if o.Files["blue-"+role+host.PostgresCAFile].Mode != 0644 {
			t.Fatal("unprivileged native cannot read source PostgreSQL trust")
		}
		if _, ok := o.Files["green-"+role+host.PostgresCAFile]; ok {
			t.Fatal("green installed trust must come from genuine prepare")
		}
		blue := o.Files["blue-"+role+host.ArtifactDirectory+"/config.yaml"].Data
		green := o.Files["green-"+role+host.ArtifactDirectory+"/config.yaml"].Data
		if !bytes.Equal(blue, green) {
			t.Fatal("source/destination staged config differs")
		}
		c, err := config.Decode(bytes.NewReader(green))
		if err != nil {
			t.Fatal(err)
		}
		if c.ValidateHandoffPins() == nil {
			t.Fatal("fabricated signed source binding")
		}
		var manifest host.Manifest
		if err = json.Unmarshal(o.Files["green-"+role+host.ArtifactManifest].Data, &manifest); err != nil {
			t.Fatal(err)
		}
		if manifest.ConfigSHA256 != digest(green) || manifest.PostgresCASHA256 != s.PostgresCA.SHA256 || manifest.ApplicationSHA256 != p.Application.SHA256 || len(manifest.Artifacts) != 62 {
			t.Fatal("manifest not derived from exact candidates")
		}
	}
	var e struct {
		Nodes   map[string]struct{ Pin string }
		Passive struct{ Manifests map[string]string }
	}
	if err = json.Unmarshal(o.Files["outer"+seed.ControlRoot+"/enrollment.json"].Data, &e); err != nil {
		t.Fatal(err)
	}
	if len(e.Nodes) != 4 || len(e.Passive.Manifests) != 0 {
		t.Fatal("candidate became passive proof")
	}
	for _, n := range e.Nodes {
		if n.Pin != "" {
			t.Fatal("candidate signed a source key")
		}
	}
	for n := range o.Files {
		if strings.Contains(n, "parallel-active") || strings.Contains(n, "parallel-primary.json") || strings.Contains(n, "passive-seed.json") {
			t.Fatal("invented product/observer evidence")
		}
	}
	files["source/var/lib/cloud-8021x/certificate-state.json"] = []byte("replacement")
	if _, err = assemble(p, s, files, m); err == nil {
		t.Fatal("changed original source accepted")
	}
}
