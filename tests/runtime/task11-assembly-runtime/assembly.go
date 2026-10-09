package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"regexp"
	"strings"

	"github.com/CampusTech/cloud-8021x/internal/adoption"
	"github.com/CampusTech/cloud-8021x/internal/domain"
	"github.com/CampusTech/cloud-8021x/internal/privileged/host"
	seed "github.com/CampusTech/cloud-8021x/tests/runtime/task11-assembly-seed/contract"
	"gopkg.in/yaml.v3"
)

type binaryPin struct{ Path, SHA256 string }
type plan struct {
	Schema                                                            int
	OriginalDirectory, InputSHA256, ArtifactDirectory, ManifestSHA256 string
	Application, Controller, Observer, Cloud                          binaryPin
	ApplicationSourceSHA, ObserverSourceSHA256, CloudSourceSHA256     string
	PrimitiveSeedSHA256, PrimitiveExpectedSHA256, Transition          string
	MachineIDs                                                        map[string]string
}
type candidate struct {
	Data                 []byte `json:"-"`
	SHA256, Owner, Group string
	Mode                 uint32
}
type reference struct{ Source, Destination, SHA256 string }
type output struct {
	Files      map[string]candidate
	References map[string][]reference
}

func (p plan) validate() error {
	if p.Schema != 1 || !regexp.MustCompile(`^[0-9a-f]{40}$`).MatchString(p.ApplicationSourceSHA) || len(p.MachineIDs) != 4 {
		return errors.New("complete independently pinned assembly plan required")
	}
	for _, v := range []string{p.InputSHA256, p.ManifestSHA256, p.Application.SHA256, p.Controller.SHA256, p.Observer.SHA256, p.Cloud.SHA256, p.ObserverSourceSHA256, p.CloudSourceSHA256, p.PrimitiveSeedSHA256, p.PrimitiveExpectedSHA256, p.Transition} {
		if !seed.IsSHA(v) {
			return errors.New("independent input pin missing")
		}
	}
	seen := map[string]bool{}
	for _, n := range []string{"blue-primary", "blue-secondary", "green-primary", "green-secondary"} {
		id := p.MachineIDs[n]
		if !regexp.MustCompile(`^[0-9a-f]{32}$`).MatchString(id) || seen[id] {
			return errors.New("four distinct builder-assigned machine IDs required")
		}
		seen[id] = true
	}
	return nil
}
func verifySeed(s seed.Input, files map[string][]byte) error {
	if err := s.Validate(); err != nil {
		return err
	}
	if err := validateOriginalFiles(files); err != nil {
		return err
	}
	if len(files) != len(s.Files) {
		return errors.New("finalized tree inventory differs")
	}
	for name, want := range s.Files {
		if len(files[name]) == 0 || adoption.Digest(files[name]) != want {
			return errors.New("finalized private seed pin differs")
		}
	}
	var original struct {
		Schema int
		Files  map[string]string
	}
	if domain.DecodeJSONStrict(files["original-manifest.json"], &original) != nil || original.Schema != 1 || len(original.Files) != 20 {
		return errors.New("original twenty-file manifest absent")
	}
	for _, name := range originalNames {
		sha := original.Files[name]
		if sha == "" || s.Files[name] != sha {
			return errors.New("original provenance differs from final seed")
		}
	}
	return nil
}
func secretValues(s seed.Input, raw []byte, blue bool) (map[string][]byte, error) {
	// Full API seed stays separately byte-pinned. Only this typed projection is consumed.
	var doc struct {
		Secrets map[string]map[string]string `json:"secrets"`
	}
	if json.Unmarshal(raw, &doc) != nil {
		return nil, errors.New("invalid seed secret projection")
	}
	refs := append([]seed.Credential(nil), s.Credentials...)
	if blue {
		for i, v := range refs {
			for _, b := range s.SourceCredentials {
				if v.File == b.File {
					refs[i] = b
				}
			}
		}
	}
	out := map[string][]byte{}
	for _, v := range refs {
		resource := strings.Replace(v.Resource, "projects/"+s.Project+"/", "projects/"+s.ProjectNumber+"/", 1)
		versions := doc.Secrets[resource]
		if len(versions) != 1 {
			return nil, errors.New("exact original secret version required")
		}
		b, err := base64.StdEncoding.Strict().DecodeString(versions["1"])
		if err != nil || len(b) == 0 || len(b) > 8192 {
			return nil, errors.New("bounded private credential required")
		}
		out[v.File] = b
	}
	return out, nil
}
func assemble(p plan, s seed.Input, files map[string][]byte, m host.Manifest) (output, error) {
	out := output{Files: map[string]candidate{}, References: map[string][]reference{}}
	if err := p.validate(); err != nil {
		return out, err
	}
	if err := verifySeed(s, files); err != nil {
		return out, err
	}
	if err := m.Validate("arm64"); err != nil {
		return out, err
	}
	if len(m.Artifacts) != 62 {
		return out, errors.New("reviewed exact62 package closure required")
	}
	add := func(node, dst string, b []byte, owner, group string, mode uint32) error {
		key := node + dst
		if !path.IsAbs(dst) || path.Clean(dst) != dst || len(b) == 0 {
			return errors.New("invalid candidate destination")
		}
		if _, exists := out.Files[key]; exists {
			return errors.New("duplicate candidate destination")
		}
		out.Files[key] = candidate{bytes.Clone(b), adoption.Digest(b), owner, group, mode}
		return nil
	}
	nodes := map[string]map[string]string{}
	for _, role := range []string{"primary", "secondary"} {
		c, err := roleConfig(s, role, p.Transition)
		if err != nil {
			return out, err
		}
		if err = c.Validate(); err != nil {
			return out, err
		}
		if err = c.ValidateBootstrap(); err != nil {
			return out, err
		}
		raw, err := yaml.Marshal(c)
		if err != nil {
			return out, err
		}
		m.ConfigSHA256 = adoption.Digest(raw)
		m.PostgresCASHA256 = s.PostgresCA.SHA256
		m.ApplicationSHA256 = p.Application.SHA256
		m.ApplicationVersion = p.ApplicationSourceSHA
		manifest, err := json.Marshal(m)
		if err != nil {
			return out, err
		}
		for _, color := range []string{"blue", "green"} {
			node := color + "-" + role
			nodes[node] = map[string]string{"MachineID": p.MachineIDs[node], "Hostname": "task11-" + node, "Pin": "", "ConfigSHA256": adoption.Digest(raw)}
			for dst, b := range map[string][]byte{host.ArtifactDirectory + "/config.yaml": raw, host.ArtifactManifest: manifest, host.IncomingPostgresCAFile: files[s.PostgresCA.Path]} {
				if err = add(node, dst, b, "root", "root", 0600); err != nil {
					return out, err
				}
			}
			out.References[node] = []reference{{p.Application.Path, host.ArtifactDirectory + "/cloud-8021x", p.Application.SHA256}, {p.Controller.Path, "/usr/local/libexec/task11-acceptance", p.Controller.SHA256}, {p.Observer.Path, "/usr/local/libexec/task11-passive-audit", p.Observer.SHA256}}
			for _, a := range m.Artifacts {
				name := a.Name + "_" + a.Version + "_" + a.Architecture + ".deb"
				out.References[node] = append(out.References[node], reference{path.Join(p.ArtifactDirectory, name), host.ArtifactDirectory + "/" + name, a.SHA256})
			}
			if color == "blue" {
				if err = add(node, host.PostgresCAFile, files[s.PostgresCA.Path], "root", "root", 0644); err != nil {
					return out, err
				}
				source, err := sourceCandidates(s, files, role, p.Transition)
				if err != nil {
					return out, err
				}
				for dst, f := range source {
					if err = add(node, dst, f.Data, f.Owner, f.Group, f.Mode); err != nil {
						return out, err
					}
				}
				out.References[node] = append(out.References[node], reference{p.Application.Path, "/usr/local/bin/cloud-8021x", p.Application.SHA256}, reference{p.Application.Path, "/usr/local/bin/acme-authz-webhook", p.Application.SHA256})
			}
		}
	}
	enrollment := struct {
		Schema                              int
		ApplicationSHA256, ControllerSHA256 string
		Nodes                               map[string]map[string]string
		Cloud, Passive                      map[string]any
	}{1, p.Application.SHA256, p.Controller.SHA256, nodes, map[string]any{"HelperSHA256": p.Cloud.SHA256, "PrimitiveSeedSHA256": p.PrimitiveSeedSHA256, "PrimitiveExpectedSHA256": p.PrimitiveExpectedSHA256, "InstalledSeedSHA256": s.InstalledSeedSHA256, "OriginalStateSHA256": s.OriginalStateSHA256}, map[string]any{"ObserverSHA256": p.Observer.SHA256, "ObserverSourceSHA256": p.ObserverSourceSHA256, "CloudSourceSHA256": p.CloudSourceSHA256, "ApplicationSourceSHA": p.ApplicationSourceSHA, "OriginalSeedSHA256": s.OriginalManifestSHA256, "Manifests": map[string]string{}}}
	raw, err := json.Marshal(enrollment)
	if err != nil {
		return out, err
	}
	if err = add("outer", seed.ControlRoot+"/enrollment.json", raw, "root", "root", 0600); err != nil {
		return out, err
	}
	out.References["outer"] = []reference{{p.Controller.Path, "/usr/local/libexec/task11-acceptance", p.Controller.SHA256}, {p.Cloud.Path, "/usr/local/libexec/task11-cloud-contract", p.Cloud.SHA256}}
	return out, nil
}
func invalidCandidate(err error) error { return fmt.Errorf("assembly candidate refused: %w", err) }

var originalNames = []string{"spec.json", "api/seed.json", "source/etc/step-ca/certs/root_ca.crt", "source/etc/step-ca/certs/intermediate_ca.crt", "source/etc/step-ca/config/ca.json", "source/etc/step-ca/templates/x509/wifi-acme.tpl", "source/etc/step-ca-rsa/certs/root_ca.crt", "source/etc/step-ca-rsa/certs/intermediate_ca.crt", "source/etc/step-ca-rsa/config/ca.json", "source/etc/step-ca-rsa/templates/x509/wifi-scep.tpl", "source/etc/acme-authz-webhook/server.crt", "source/etc/acme-authz-webhook/server.key", "source/etc/freeradius/3.0/certs/server.pem", "source/etc/freeradius/3.0/certs/server-key.pem", "source/etc/freeradius/3.0/certs/ca.pem", "source/etc/freeradius/3.0/device-policy-cache.json", "source/var/lib/cloud-8021x/certificate-state.json", "source/etc/cloud8021x-task11-source-provenance.json", "source/var/lib/cloud-8021x/fingerprint-enforced", "source/run/radius-accounting-key"}

func validateOriginalFiles(files map[string][]byte) error {
	allowed := map[string]bool{}
	for _, name := range originalNames {
		allowed[name] = true
		if len(files[name]) == 0 {
			return errors.New("complete original source state required")
		}
	}
	for name := range files {
		if strings.HasPrefix(name, "source/") && !allowed[name] {
			return errors.New("unapproved source path")
		}
	}
	return nil
}
