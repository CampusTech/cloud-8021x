package main

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/adapters/stepca"
	"github.com/CampusTech/cloud-8021x/internal/adoption"
	"github.com/CampusTech/cloud-8021x/internal/config"
	"github.com/CampusTech/cloud-8021x/internal/domain"
	audit "github.com/CampusTech/cloud-8021x/tests/runtime/task11-passive-audit/contract"
)

type originalManifest struct {
	Schema int
	Files  map[string]string
}

var originalNames = []string{"spec.json", "api/seed.json", "source/etc/step-ca/certs/root_ca.crt", "source/etc/step-ca/certs/intermediate_ca.crt", "source/etc/step-ca/config/ca.json", "source/etc/step-ca/templates/x509/wifi-acme.tpl", "source/etc/step-ca-rsa/certs/root_ca.crt", "source/etc/step-ca-rsa/certs/intermediate_ca.crt", "source/etc/step-ca-rsa/config/ca.json", "source/etc/step-ca-rsa/templates/x509/wifi-scep.tpl", "source/etc/acme-authz-webhook/server.crt", "source/etc/acme-authz-webhook/server.key", "source/etc/freeradius/3.0/certs/server.pem", "source/etc/freeradius/3.0/certs/server-key.pem", "source/etc/freeradius/3.0/certs/ca.pem", "source/etc/freeradius/3.0/device-policy-cache.json", "source/var/lib/cloud-8021x/certificate-state.json", "source/etc/cloud8021x-task11-source-provenance.json", "source/var/lib/cloud-8021x/fingerprint-enforced", "source/run/radius-accounting-key"}

func originalManifestBytes(files map[string][]byte) ([]byte, error) {
	m := originalManifest{Schema: 1, Files: map[string]string{}}
	for _, name := range originalNames {
		if len(files[name]) == 0 {
			return nil, errors.New("immutable source input missing")
		}
		m.Files[name] = adoption.Digest(files[name])
	}
	return json.Marshal(m)
}

type seedSecrets map[string][]byte

func (s seedSecrets) Enabled(_ context.Context, name string) ([]string, error) {
	if len(s[name]) == 0 {
		return nil, errors.New("original secret missing")
	}
	return []string{name + "/versions/1"}, nil
}
func (s seedSecrets) Access(_ context.Context, name string) ([]byte, error) {
	if !strings.HasSuffix(name, "/versions/1") {
		return nil, errors.New("original secret version differs")
	}
	v := s[strings.TrimSuffix(name, "/versions/1")]
	if len(v) == 0 {
		return nil, errors.New("original secret missing")
	}
	return bytes.Clone(v), nil
}
func derivePassiveManifest(c config.Config, a adoption.Authorization, files map[string][]byte, originalPin, postgresPin string, now time.Time) (audit.Manifest, error) {
	m := audit.Manifest{Schema: 1, OriginalSeedSHA256: originalPin, CertificateStateSHA256: adoption.Digest(files["source/var/lib/cloud-8021x/certificate-state.json"]), Slots: map[string]string{}}
	if !validSHA(originalPin) || !validSHA(postgresPin) || a.Native == nil {
		return m, errors.New("original preparation inputs required")
	}
	original, err := originalManifestBytes(files)
	if err != nil || adoption.Digest(original) != originalPin {
		return m, errors.New("immutable original bundle differs")
	}
	p, err := deriveSourceProvenance(files["source/etc/freeradius/3.0/device-policy-cache.json"], files["source/var/lib/cloud-8021x/certificate-state.json"])
	if err != nil {
		return m, err
	}
	if validateBoundSourceCache(a.Policy, p) != nil || adoption.Digest(a.Certificates) != m.CertificateStateSHA256 {
		return m, errors.New("authenticated source policy/certificate provenance differs")
	}
	n := a.Native
	for path, want := range map[string][]byte{"source/etc/acme-authz-webhook/server.crt": n.WebhookCertificate, "source/etc/acme-authz-webhook/server.key": n.WebhookKey, "source/etc/step-ca/config/ca.json": n.ECConfig, "source/etc/step-ca-rsa/config/ca.json": n.RSAConfig, "source/etc/step-ca/templates/x509/wifi-acme.tpl": n.ECTemplate, "source/etc/step-ca-rsa/templates/x509/wifi-scep.tpl": n.RSATemplate} {
		if !bytes.Equal(files[path], want) {
			return m, errors.New("inherited native identity changed")
		}
	}
	var top map[string]json.RawMessage
	var encoded map[string]map[string]string
	if decodeExactJSON(files["api/seed.json"], &top) != nil || decodeExactJSON(top["secrets"], &encoded) != nil {
		return m, errors.New("original secret seed invalid")
	}
	secrets := seedSecrets{}
	defer func() {
		for _, v := range secrets {
			clear(v)
		}
	}()
	for name, versions := range encoded {
		if len(versions) != 1 {
			return m, errors.New("unexpected original secret versions")
		}
		v, e := base64.StdEncoding.DecodeString(versions["1"])
		if e != nil {
			return m, e
		}
		secrets[name] = v
	}
	prefix := "projects/111222333444/secrets/"
	materials := map[string]stepca.Material{}
	for _, kind := range []string{"ec", "rsa"} {
		names := []string{"smallstep-ca-cert", "smallstep-intermediate-cert", "smallstep-scep-decrypter-cert", "smallstep-scep-decrypter-key"}
		if kind == "rsa" {
			names = []string{"smallstep-rsa-root-cert", "smallstep-rsa-intermediate-cert", "smallstep-rsa-scep-decrypter-cert", "smallstep-rsa-scep-decrypter-key"}
		}
		mat := stepca.Material{Root: secrets[prefix+names[0]], Intermediate: secrets[prefix+names[1]], DecrypterCert: secrets[prefix+names[2]], DecrypterKey: secrets[prefix+names[3]]}
		block, _ := pem.Decode(mat.Intermediate)
		if block == nil {
			return m, errors.New("original intermediate invalid")
		}
		cert, e := x509.ParseCertificate(block.Bytes)
		if e != nil {
			return m, e
		}
		if e = stepca.Validate(mat, stepca.Kind(kind), cert.PublicKey, now); e != nil {
			return m, e
		}
		base := "source/etc/step-ca"
		if kind == "rsa" {
			base += "-rsa"
		}
		if !bytes.Equal(mat.Root, files[base+"/certs/root_ca.crt"]) || !bytes.Equal(mat.Intermediate, files[base+"/certs/intermediate_ca.crt"]) {
			return m, errors.New("original secret and native trust differ")
		}
		materials[kind] = mat
		for slot, v := range map[string][]byte{"root": mat.Root, "intermediate": mat.Intermediate, "decrypter": mat.DecrypterCert, "decrypter-key": mat.DecrypterKey} {
			m.Slots[kind+"-"+slot] = adoption.Digest(v)
		}
	}
	ec, rsa := materials["ec"], materials["rsa"]
	server, err := stepca.AdoptServer(context.Background(), secrets, ec, c.Bootstrap.ServerDNS, prefix+"radius-smallstep-server-cert", prefix+"radius-smallstep-server-key", now)
	if err != nil {
		return m, err
	}
	var spec seedSpec
	if decodeExactJSON(files["spec.json"], &spec) != nil {
		return m, errors.New("original rendering specification invalid")
	}
	_, port, err := net.SplitHostPort(c.Listeners.Webhook.Address)
	if err != nil {
		return m, err
	}
	number, err := strconv.Atoi(port)
	if err != nil {
		return m, err
	}
	rendered, err := stepca.Render(stepca.RenderOptions{ECDNS: c.Bootstrap.ECDNS, RSADNS: c.Bootstrap.RSADNS, ECKey: c.Bootstrap.ECKMS, RSAKey: c.Bootstrap.RSAKMS, ECDB: spec.ECDB, RSADB: spec.RSADB, ACME: c.Bootstrap.ACMEProvisioner, SCEP: c.Bootstrap.SCEPProvisioner, WebhookPort: number, Inventory: c.Inventory.Fleet.ManagedCertificates, RSAMaterial: rsa})
	if err != nil {
		return m, err
	}
	for path, raw := range map[string][]byte{"/etc/step-ca/config/ca.json": n.ECConfig, "/etc/step-ca-rsa/config/ca.json": n.RSAConfig} {
		if err = stepca.ValidateAdoptedConfig(raw, rendered[path]); err != nil {
			return m, err
		}
	}
	if !bytes.Equal(n.ECTemplate, rendered["/etc/step-ca/templates/x509/wifi-acme.tpl"]) || !bytes.Equal(n.RSATemplate, rendered["/etc/step-ca-rsa/templates/x509/wifi-scep.tpl"]) {
		return m, errors.New("original template differs from supported preparation")
	}
	if err = stepca.ValidateAdoptedLoopback(n.WebhookCertificate, n.WebhookKey, now); err != nil {
		return m, err
	}
	trust := bytes.Join([][]byte{ec.Intermediate, ec.Root, rsa.Intermediate, rsa.Root}, nil)
	class := files["source/run/radius-accounting-key"]
	if adoption.Digest(trust) != a.TrustSHA256 || adoption.Digest(class) != a.ClassSHA256 || !bytes.Equal(class, secrets[prefix+"radius-accounting-class-key"]) {
		return m, errors.New("authenticated Class/trust differs from original seed")
	}
	for slot, v := range map[string][]byte{"ec-config": n.ECConfig, "rsa-config": n.RSAConfig, "ec-template": n.ECTemplate, "rsa-template": n.RSATemplate, "native-server": server.Chain, "native-server-key": server.Key, "server-cache": server.Chain, "client-trust": trust, "webhook-cache": n.WebhookCertificate, "webhook-public": n.WebhookCertificate, "webhook-cache-key": n.WebhookKey, "webhook-key": n.WebhookKey, "class-key": class, "legacy-class-key": class, "inventory": a.Policy} {
		m.Slots[slot] = adoption.Digest(v)
	}
	m.Slots["postgres-ca"] = postgresPin
	return m, audit.ValidateManifest(m, audit.Request{OriginalSeedSHA256: originalPin})
}
func deactivatedInventory(c config.Config, original, publication, seed []byte) (string, error) {
	before, err := domain.DecodeSnapshot(bytes.NewReader(original))
	if err != nil {
		return "", err
	}
	after, err := domain.DecodeSnapshot(bytes.NewReader(publication))
	if err != nil {
		return "", err
	}
	var top map[string]json.RawMessage
	var remote remoteContract
	if decodeExactJSON(seed, &top) != nil || decodeExactJSON(top["contract"], &remote) != nil {
		return "", errors.New("approved remote host projection absent")
	}
	if _, err = approvedGreenHosts(seed, remote.ApplicationSHA256); err != nil {
		return "", err
	}
	for i, host := range remote.Fleet.Hosts {
		var mdm struct {
			EnrollmentStatus string          `json:"enrollment_status"`
			Profiles         json.RawMessage `json:"profiles"`
		}
		platform := "darwin"
		if i == 1 {
			platform = "windows"
		}
		if host.TeamID != 1 || host.Platform != platform || host.Serial != "" || decodeExactJSON(host.MDM, &mdm) != nil || mdm.EnrollmentStatus != "On" {
			return "", errors.New("approved remote enrollment/group projection differs")
		}
	}
	if after.Version != 2 || !reflect.DeepEqual(before.Certificates, after.Certificates) || len(after.HardwareSerials) != 0 || len(after.Identities) != 2 {
		return "", errors.New("original certificate authority changed")
	}
	apple := before.Identities[syntheticDevice]
	if apple == nil {
		return "", errors.New("original Apple identity missing")
	}
	for id, rec := range after.Identities {
		if rec == nil {
			return "", errors.New("ambiguous published identity")
		}
		switch id {
		case syntheticDevice:
			a, b := *apple, *rec
			a.ObservedAt = nil
			b.ObservedAt = nil
			if !reflect.DeepEqual(a, b) || (rec.ObservedAt != nil && !reflect.DeepEqual(apple.ObservedAt, rec.ObservedAt)) {
				return "", errors.New("original Apple identity provenance changed")
			}
		case syntheticWindows:
			want := domain.DeviceRecord{DeviceID: "fleet:2", Groups: []domain.GroupID{"fleet:1"}, Enrolled: true}
			if !reflect.DeepEqual(*rec, want) || remote.Fleet.Hosts[1].TeamID != 1 {
				return "", errors.New("published Windows identity exceeds approved host projection")
			}
		default:
			return "", errors.New("unapproved published identity")
		}
	}
	if after.Identities[syntheticDevice] == nil || after.Identities[syntheticWindows] == nil {
		return "", errors.New("both approved published identities required")
	}
	if _, err = semanticDisplay(c, after); err != nil {
		return "", err
	}
	return adoption.Digest(publication), nil
}
