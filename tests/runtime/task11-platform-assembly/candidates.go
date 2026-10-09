package main

import (
	"bytes"
	"debug/buildinfo"
	"encoding/json"
	"errors"
	"os"
	"path"
	"strings"

	"github.com/CampusTech/cloud-8021x/internal/config"
	"github.com/CampusTech/cloud-8021x/internal/domain"
	"github.com/CampusTech/cloud-8021x/internal/privileged/host"
	seed "github.com/CampusTech/cloud-8021x/tests/runtime/task11-assembly-seed/contract"
)

type candidate struct {
	SHA256, Owner, Group string
	Mode                 uint32
}
type reference struct{ Source, Destination, SHA256 string }
type candidateIndex struct {
	Files      map[string]candidate
	References map[string][]reference
}
type inputs struct {
	Plan                       plan
	Seed                       seed.Input
	Index                      candidateIndex
	Files, Original, Primitive map[string][]byte
	Packages                   host.Manifest
}

func incoming() map[string]candidate {
	return map[string]candidate{host.ArtifactDirectory + "/config.yaml": {Owner: "root", Group: "root", Mode: 0600}, host.ArtifactManifest: {Owner: "root", Group: "root", Mode: 0600}, host.IncomingPostgresCAFile: {Owner: "root", Group: "root", Mode: 0600}}
}
func blueDestinations(s seed.Input) map[string]candidate {
	out := incoming()
	add := func(n, o, g string, m uint32) { out[n] = candidate{Owner: o, Group: g, Mode: m} }
	for _, base := range []string{"/etc/step-ca", "/etc/step-ca-rsa"} {
		for _, f := range []string{"certs/root_ca.crt", "certs/intermediate_ca.crt", "config/ca.json"} {
			add(base+"/"+f, "root", "root", 0600)
		}
	}
	add("/etc/step-ca/templates/x509/wifi-acme.tpl", "root", "root", 0600)
	add("/etc/step-ca-rsa/templates/x509/wifi-scep.tpl", "root", "root", 0600)
	for _, f := range []string{"server.pem", "server-cert.pem", "server-key.pem", "ca.pem"} {
		add("/etc/freeradius/3.0/certs/"+f, "root", "freerad", 0640)
	}
	for _, f := range []string{"radiusd.conf", "dictionary", "clients.conf", "mods-enabled/eap", "mods-enabled/rest", "mods-enabled/sql", "mods-enabled/accounting_detail", "mods-enabled/auth_detail", "mods-enabled/always", "sites-enabled/default", "sites-enabled/certificate", "sites-enabled/buffered", "sites-enabled/health"} {
		add("/etc/freeradius/3.0/"+f, "root", "freerad", 0640)
	}
	add("/etc/freeradius/3.0/device-policy-cache.json", "root", "freerad", 0644)
	for _, f := range []string{"server.crt", "server.key"} {
		add("/etc/acme-authz-webhook/"+f, "root", "cloud8021x", 0640)
	}
	for _, f := range []string{"/etc/cloud-8021x/client-cas.pem", "/etc/acme-authz-webhook/client-cas.pem", host.PostgresCAFile} {
		add(f, "root", "root", 0644)
	}
	for _, f := range []string{"/etc/cloud8021x-task11-source.yaml", "/etc/cloud-8021x/config.yaml"} {
		add(f, "root", "cloud8021x", 0640)
	}
	add("/etc/cloud8021x-task11-source-provenance.json", "root", "root", 0444)
	for _, f := range []string{"/var/lib/cloud-8021x/certificate-state.json", "/var/lib/cloud-8021x/fingerprint-enforced", "/etc/cloud8021x-task11-webhook.env", "/etc/cloud8021x-task11-credentials/legacy-class"} {
		add(f, "root", "root", 0600)
	}
	add("/run/radius-accounting-key", "cloud8021x", "cloud8021x", 0600)
	for _, r := range s.Credentials {
		o := map[string]string{"runtime": "cloud8021x", "root": "root", "collector": "dd-agent"}[r.Owner]
		add(r.File, o, o, 0600)
		add("/etc/cloud8021x-task11-credentials/"+path.Base(r.File), "root", "root", 0600)
	}
	for _, f := range []string{"step-ca.service", "step-ca-rsa.service", "task11-source-policy.service", "acme-authz-webhook.service", "radius-source-refresh.service", "radius-source-refresh.timer", "freeradius.service.d/cloud-8021x.conf"} {
		add("/etc/systemd/system/"+f, "root", "root", 0644)
	}
	add("/etc/tmpfiles.d/task11-source.conf", "root", "root", 0644)
	add("/etc/sudoers.d/cloud-8021x", "root", "root", 0440)
	return out
}
func validateCandidateIndex(p plan, s seed.Input, index candidateIndex) error {
	expected := map[string]candidate{"outer" + controlRoot + "/enrollment.json": {Owner: "root", Group: "root", Mode: 0600}}
	for _, n := range p.Nodes {
		set := incoming()
		if strings.HasPrefix(n.Name, "blue-") {
			set = blueDestinations(s)
		}
		for f, m := range set {
			expected[n.Name+f] = m
		}
	}
	if len(index.Files) != len(expected) || len(index.References) != 5 {
		return errors.New("closed candidate inventory differs")
	}
	for n, w := range expected {
		v, ok := index.Files[n]
		if !ok || !seed.IsSHA(v.SHA256) || v.Owner != w.Owner || v.Group != w.Group || v.Mode != w.Mode {
			return errors.New("candidate destination or privilege differs")
		}
	}
	return nil
}
func loadInputs(p plan) (inputs, error) {
	out := inputs{Plan: p, Files: map[string][]byte{}, Original: map[string][]byte{}, Primitive: map[string][]byte{}}
	if e := p.validate(); e != nil {
		return out, e
	}
	read := func(name, sha string, limit int64, private bool) ([]byte, error) {
		return readPinned(name, sha, limit, private)
	}
	raw, e := read(originalRoot+"/assembly-input.json", p.InputSHA256, 1<<20, true)
	if e != nil {
		return out, e
	}
	if domain.DecodeJSONStrict(raw, &out.Seed) != nil {
		return out, errors.New("strict final seed input required")
	}
	if e = out.Seed.Validate(); e != nil {
		return out, e
	}
	total := 0
	privateBytes := 0
	for f, sha := range out.Seed.Files {
		b, e := read(originalRoot+"/"+f, sha, 8<<20, true)
		if e != nil {
			return out, e
		}
		total += len(b)
		privateBytes += len(b)
		if total > 32<<20 {
			return out, errors.New("original aggregate exceeds bound")
		}
		out.Original[f] = b
	}
	raw, e = read(candidateRoot+"/candidate-index.json", p.CandidateSHA256, 2<<20, true)
	if e != nil {
		return out, e
	}
	if domain.DecodeJSONStrict(raw, &out.Index) != nil {
		return out, errors.New("strict candidate index required")
	}
	if e = validateCandidateIndex(p, out.Seed, out.Index); e != nil {
		return out, e
	}
	total = 0
	for f, c := range out.Index.Files {
		b, e := read(candidateRoot+"/files/"+f, c.SHA256, 8<<20, true)
		if e != nil {
			return out, e
		}
		total += len(b)
		privateBytes += len(b)
		if total > 32<<20 {
			return out, errors.New("candidate aggregate exceeds bound")
		}
		out.Files[f] = b
	}
	var packageInput struct {
		Schema          int             `json:"schema"`
		Architecture    string          `json:"architecture"`
		CollectorSHA256 string          `json:"collector_sha256"`
		Artifacts       []host.Artifact `json:"artifacts"`
	}
	raw, e = read(publicRoot+"/artifacts/package-manifest.json", p.PackageManifestSHA256, 1<<20, false)
	if e != nil {
		return out, e
	}
	if domain.DecodeJSONStrict(raw, &packageInput) != nil {
		return out, errors.New("package manifest invalid")
	}
	out.Packages = host.Manifest{Schema: packageInput.Schema, Architecture: packageInput.Architecture, CollectorSHA256: packageInput.CollectorSHA256, Artifacts: packageInput.Artifacts, PostgresCASHA256: out.Seed.PostgresCA.SHA256}
	if e = out.Packages.Validate("arm64"); e != nil || len(out.Packages.Artifacts) != 62 {
		return out, errors.New("exact reviewed62 closure required")
	}
	expectedArchiveFiles := map[string]bool{"package-manifest.json": true}
	for _, a := range out.Packages.Artifacts {
		expectedArchiveFiles[a.Name+"_"+a.Version+"_"+a.Architecture+".deb"] = true
	}
	entries, err := os.ReadDir(publicRoot + "/artifacts")
	if err != nil || len(entries) != len(expectedArchiveFiles) {
		return out, errors.New("closed public archive directory required")
	}
	for _, entry := range entries {
		if entry.IsDir() || !expectedArchiveFiles[entry.Name()] {
			return out, errors.New("unreviewed archive-directory entry")
		}
	}
	var stagedBytes int64
	for _, a := range out.Packages.Artifacts {
		name := a.Name + "_" + a.Version + "_" + a.Architecture + ".deb"
		f, e := openPinned(publicRoot+"/artifacts/"+name, a.SHA256, 256<<20, false)
		if e != nil {
			return out, e
		}
		st, err := f.Stat()
		_ = f.Close()
		if err != nil {
			return out, err
		}
		stagedBytes += st.Size()
	}
	raw, e = read(publicRoot+"/cloud-8021x", p.ApplicationSHA256, 160<<20, false)
	if e != nil {
		return out, e
	}
	bi, e := buildinfo.Read(bytes.NewReader(raw))
	if e != nil {
		return out, errors.New("application build identity missing")
	}
	settings := map[string]string{}
	for _, v := range bi.Settings {
		settings[v.Key] = v.Value
	}
	if bi.Path != "github.com/CampusTech/cloud-8021x/cmd/cloud-8021x" || settings["GOOS"] != "linux" || settings["GOARCH"] != "arm64" || settings["vcs.revision"] != p.ApplicationSourceSHA || settings["vcs.modified"] != "false" {
		return out, errors.New("clean shipping application binding differs")
	}
	clear(raw)
	executables := []pin{{publicRoot + "/cloud-8021x", p.ApplicationSHA256}}
	for _, h := range p.Helpers {
		executables = append(executables, h)
	}
	for _, h := range executables {
		f, e := openPinned(h.Path, h.SHA256, 160<<20, false)
		if e != nil {
			return out, e
		}
		st, err := f.Stat()
		_ = f.Close()
		if err != nil || st.Mode().Perm()&0111 == 0 {
			return out, errors.New("staged executable mode missing")
		}
		stagedBytes += st.Size()
	}
	if stagedBytes > p.Budget.StagingBytes {
		return out, errors.New("actual public staging exceeds reviewed budget")
	}
	for f, sha := range primitivePins(out) {
		b, err := read(controlRoot+"/primitive-api/"+f, sha, 8<<20, true)
		if err != nil {
			return out, err
		}
		privateBytes += len(b)
		out.Primitive[f] = b
	}
	if int64(privateBytes) > p.Budget.PrivateBytes {
		return out, errors.New("actual private staged inputs exceed measured budget")
	}
	return out, out.validateBindings()
}
func (in inputs) validateBindings() error {
	p := in.Plan
	expectedRefs := map[string][]reference{}
	for _, n := range p.Nodes {
		refs := []reference{{publicRoot + "/cloud-8021x", host.ArtifactDirectory + "/cloud-8021x", p.ApplicationSHA256}, {p.Helpers["task11-acceptance"].Path, "/usr/local/libexec/task11-acceptance", p.ControllerSHA256}, {p.Helpers["task11-passive-audit"].Path, "/usr/local/libexec/task11-passive-audit", p.ObserverSHA256}}
		for _, a := range in.Packages.Artifacts {
			f := a.Name + "_" + a.Version + "_" + a.Architecture + ".deb"
			refs = append(refs, reference{publicRoot + "/artifacts/" + f, host.ArtifactDirectory + "/" + f, a.SHA256})
		}
		if strings.HasPrefix(n.Name, "blue-") {
			refs = append(refs, reference{publicRoot + "/cloud-8021x", "/usr/local/bin/cloud-8021x", p.ApplicationSHA256}, reference{publicRoot + "/cloud-8021x", "/usr/local/bin/acme-authz-webhook", p.ApplicationSHA256})
		}
		expectedRefs[n.Name] = refs
		cfgRaw := in.Files[n.Name+host.ArtifactDirectory+"/config.yaml"]
		c, e := config.Decode(bytes.NewReader(cfgRaw))
		if e != nil || c.ValidateBootstrap() != nil || c.Deployment.Instance != "task11-green-"+strings.TrimPrefix(strings.TrimPrefix(n.Name, "blue-"), "green-") || c.Database.Name != seed.Database {
			return errors.New("complete role config binding differs")
		}
		var m host.Manifest
		if domain.DecodeJSONStrict(in.Files[n.Name+host.ArtifactManifest], &m) != nil || m.ConfigSHA256 != digest(cfgRaw) || m.ApplicationSHA256 != p.ApplicationSHA256 || m.PostgresCASHA256 != in.Seed.PostgresCA.SHA256 || m.ApplicationVersion != p.ApplicationSourceSHA || m.Validate("arm64") != nil || !sameJSON(m.Artifacts, in.Packages.Artifacts) || m.CollectorSHA256 != in.Packages.CollectorSHA256 {
			return errors.New("incoming manifest binding differs")
		}
	}
	expectedRefs["outer"] = []reference{{p.Helpers["task11-acceptance"].Path, "/usr/local/libexec/task11-acceptance", p.ControllerSHA256}, {p.Helpers["task11-cloud-contract"].Path, "/usr/local/libexec/task11-cloud-contract", p.CloudSHA256}}
	if !sameJSON(expectedRefs, in.Index.References) {
		return errors.New("unapproved public reference destination or hash")
	}
	var e struct {
		Schema                              int
		ApplicationSHA256, ControllerSHA256 string
		Nodes                               map[string]struct{ MachineID, Hostname, Pin, ConfigSHA256 string }
		Cloud                               struct{ HelperSHA256, PrimitiveSeedSHA256, PrimitiveExpectedSHA256, InstalledSeedSHA256, OriginalStateSHA256 string }
		Passive                             struct {
			ObserverSHA256, ObserverSourceSHA256, CloudSourceSHA256, ApplicationSourceSHA, OriginalSeedSHA256 string
			Manifests                                                                                         map[string]string
		}
	}
	if domain.DecodeJSONStrict(in.Files["outer"+controlRoot+"/enrollment.json"], &e) != nil || e.Schema != 1 || e.ApplicationSHA256 != p.ApplicationSHA256 || e.ControllerSHA256 != p.ControllerSHA256 || len(e.Nodes) != 4 || len(e.Passive.Manifests) != 0 {
		return errors.New("unsigned enrollment required")
	}
	for _, n := range p.Nodes {
		v := e.Nodes[n.Name]
		if v.MachineID != n.MachineID || v.Hostname != "task11-"+n.Name || v.Pin != "" || v.ConfigSHA256 != digest(in.Files[n.Name+host.ArtifactDirectory+"/config.yaml"]) {
			return errors.New("node enrollment identity differs")
		}
	}
	if e.Cloud.HelperSHA256 != p.CloudSHA256 || e.Cloud.PrimitiveSeedSHA256 != p.PrimitiveSeedSHA256 || e.Cloud.PrimitiveExpectedSHA256 != p.PrimitiveExpectedSHA256 || e.Cloud.InstalledSeedSHA256 != in.Seed.InstalledSeedSHA256 || e.Cloud.OriginalStateSHA256 != in.Seed.OriginalStateSHA256 || e.Passive.ObserverSHA256 != p.ObserverSHA256 || e.Passive.ObserverSourceSHA256 != p.ObserverSourceSHA256 || e.Passive.CloudSourceSHA256 != p.CloudSourceSHA256 || e.Passive.ApplicationSourceSHA != p.ApplicationSourceSHA || e.Passive.OriginalSeedSHA256 != in.Seed.OriginalManifestSHA256 {
		return errors.New("independent enrollment pins differ")
	}
	return nil
}

func sameJSON(a, b any) bool {
	x, e := json.Marshal(a)
	y, f := json.Marshal(b)
	return e == nil && f == nil && bytes.Equal(x, y)
}

func primitivePins(in inputs) map[string]string {
	return map[string]string{"seed.json": in.Plan.PrimitiveSeedSHA256, "driver-input.json": in.Plan.PrimitiveInputSHA256, "expected.json": in.Plan.PrimitiveExpectedSHA256, "ca.pem": in.Seed.APICA.SHA256, "tls.pem": in.Seed.Files["api/tls.pem"], "tls.key": in.Seed.Files["api/tls.key"]}
}
