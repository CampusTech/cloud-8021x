package main

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/adapters/stepca"
	"github.com/CampusTech/cloud-8021x/internal/adoption"
	"github.com/CampusTech/cloud-8021x/internal/domain"
	"github.com/CampusTech/cloud-8021x/internal/migration"
)

type seedSpec struct {
	Project, ECDNS, RSADNS, ServerDNS, ECDB, RSADB string
	ObservedAt                                     time.Time
	Remote                                         *remoteSeedSpec
}
type seedCA struct {
	material           stepca.Material
	root, intermediate *x509.Certificate
	rootKey, kms       crypto.Signer
}

func keyPEM(k crypto.Signer) ([]byte, error) {
	b, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: b}), nil
}
func issue(template, parent *x509.Certificate, public crypto.PublicKey, signer crypto.Signer) (*x509.Certificate, []byte, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}
	template.SerialNumber = serial
	raw, err := x509.CreateCertificate(rand.Reader, template, parent, public, signer)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(raw)
	return cert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: raw}), err
}
func syntheticCA(kind stepca.Kind, now time.Time) (seedCA, error) {
	var c seedCA
	var err error
	if kind == stepca.EC {
		c.rootKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	} else {
		c.rootKey, err = rsa.GenerateKey(rand.Reader, 4096)
	}
	if err != nil {
		return c, err
	}
	if kind == stepca.EC {
		c.kms, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	} else {
		c.kms, err = rsa.GenerateKey(rand.Reader, 2048)
	}
	if err != nil {
		return c, err
	}
	root := &x509.Certificate{Subject: pkix.Name{CommonName: "Task11 synthetic " + string(kind) + " root"}, NotBefore: now.Add(-time.Hour), NotAfter: now.AddDate(2, 0, 0), IsCA: true, BasicConstraintsValid: true, MaxPathLen: 1, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	c.root, c.material.Root, err = issue(root, root, c.rootKey.Public(), c.rootKey)
	if err != nil {
		return c, err
	}
	inter := &x509.Certificate{Subject: pkix.Name{CommonName: "Task11 synthetic " + string(kind) + " intermediate"}, NotBefore: now.Add(-time.Hour), NotAfter: now.AddDate(1, 0, 0), IsCA: true, BasicConstraintsValid: true, MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	c.intermediate, c.material.Intermediate, err = issue(inter, c.root, c.kms.Public(), c.rootKey)
	if err != nil {
		return c, err
	}
	decKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return c, err
	}
	dec := &x509.Certificate{Subject: pkix.Name{CommonName: "Task11 synthetic " + string(kind) + " decrypter"}, NotBefore: now.Add(-time.Hour), NotAfter: now.AddDate(1, 0, 0), BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}}
	parent, signer := c.intermediate, c.kms
	if kind == stepca.EC {
		parent, signer = c.root, c.rootKey
	}
	_, c.material.DecrypterCert, err = issue(dec, parent, decKey.Public(), signer)
	if err != nil {
		return c, err
	}
	c.material.DecrypterKey, err = keyPEM(decKey)
	if err != nil {
		return c, err
	}
	return c, stepca.Validate(c.material, kind, c.kms.Public(), now)
}
func generateSeed(s seedSpec) (map[string][]byte, error) {
	if !regexp.MustCompile(`^task11-[a-z0-9-]{1,30}$`).MatchString(s.Project) || s.ObservedAt.IsZero() || s.ObservedAt.Nanosecond() != 0 {
		return nil, errors.New("bounded synthetic project and original whole-second UTC observation required")
	}
	for _, dsn := range []string{s.ECDB, s.RSADB} {
		u, err := url.Parse(dsn)
		if err != nil || u.Hostname() != "10.203.11.11" || u.Query().Get("sslmode") != "verify-full" {
			return nil, errors.New("only owned TLS PostgreSQL endpoint allowed")
		}
	}
	now := s.ObservedAt.UTC()
	files := map[string][]byte{}
	specBytes, err := json.Marshal(s)
	if err != nil {
		return nil, err
	}
	files["spec.json"] = specBytes
	ec, err := syntheticCA(stepca.EC, now)
	if err != nil {
		return nil, err
	}
	rsaCA, err := syntheticCA(stepca.RSA, now)
	if err != nil {
		return nil, err
	}
	secrets := map[string]map[string]string{}
	secret := func(name string, b []byte) {
		secrets["projects/111222333444/secrets/"+name] = map[string]string{"1": base64.StdEncoding.EncodeToString(b)}
	}
	for _, v := range []struct {
		ca         seedCA
		base, kind string
		names      []string
	}{{ec, "/etc/step-ca", "ec", []string{"smallstep-ca-cert", "smallstep-intermediate-cert", "smallstep-scep-decrypter-cert", "smallstep-scep-decrypter-key"}}, {rsaCA, "/etc/step-ca-rsa", "rsa", []string{"smallstep-rsa-root-cert", "smallstep-rsa-intermediate-cert", "smallstep-rsa-scep-decrypter-cert", "smallstep-rsa-scep-decrypter-key"}}} {
		files["source"+v.base+"/certs/root_ca.crt"] = v.ca.material.Root
		files["source"+v.base+"/certs/intermediate_ca.crt"] = v.ca.material.Intermediate
		for i, b := range [][]byte{v.ca.material.Root, v.ca.material.Intermediate, v.ca.material.DecrypterCert, v.ca.material.DecrypterKey} {
			secret(v.names[i], b)
		}
		files["api/"+v.kind+"-kms.pem"], err = keyPEM(v.ca.kms)
		if err != nil {
			return nil, err
		}
		files["private-original/"+v.kind+"-root.pem"], err = keyPEM(v.ca.rootKey)
		if err != nil {
			return nil, err
		}
	}
	keyPrefix := "cloudkms:projects/" + s.Project + "/locations/us-central1/keyRings/task11/cryptoKeys/"
	rendered, err := stepca.Render(stepca.RenderOptions{ECDNS: s.ECDNS, RSADNS: s.RSADNS, ECKey: keyPrefix + "ec/cryptoKeyVersions/1", RSAKey: keyPrefix + "rsa/cryptoKeyVersions/1", ECDB: s.ECDB, RSADB: s.RSADB, ACME: "wifi-acme", SCEP: "wifi-scep", WebhookPort: 9080, Inventory: true, RSAMaterial: rsaCA.material})
	if err != nil {
		return nil, err
	}
	for p, b := range rendered {
		files["source"+p] = b
	}
	webhookKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	webhook := &x509.Certificate{Subject: pkix.Name{CommonName: "localhost"}, DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, NotBefore: now.Add(-time.Hour), NotAfter: now.AddDate(1, 0, 0), BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	_, files["source/etc/acme-authz-webhook/server.crt"], err = issue(webhook, webhook, webhookKey.Public(), webhookKey)
	if err != nil {
		return nil, err
	}
	files["source/etc/acme-authz-webhook/server.key"], err = keyPEM(webhookKey)
	if err != nil {
		return nil, err
	}
	if err = stepca.ValidateAdoptedLoopback(files["source/etc/acme-authz-webhook/server.crt"], files["source/etc/acme-authz-webhook/server.key"], now); err != nil {
		return nil, err
	}
	serverKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	server := &x509.Certificate{Subject: pkix.Name{CommonName: s.ServerDNS}, DNSNames: []string{s.ServerDNS}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(90 * 24 * time.Hour), BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	_, serverPEM, err := issue(server, ec.intermediate, serverKey.Public(), ec.kms)
	if err != nil {
		return nil, err
	}
	serverPrivate, err := keyPEM(serverKey)
	if err != nil {
		return nil, err
	}
	if err = stepca.ValidateServerCache(stepca.ServerCertificate{Certificate: serverPEM, Key: serverPrivate}, ec.material, s.ServerDNS, now); err != nil {
		return nil, err
	}
	secret("radius-smallstep-server-cert", serverPEM)
	secret("radius-smallstep-server-key", serverPrivate)
	files["source/etc/freeradius/3.0/certs/server.pem"] = append(bytes.Clone(serverPEM), ec.material.Intermediate...)
	files["source/etc/freeradius/3.0/certs/server-key.pem"] = serverPrivate
	files["source/etc/freeradius/3.0/certs/ca.pem"] = append(bytes.Clone(ec.material.Root), rsaCA.material.Root...)
	clientKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	device := "11111111-2222-4333-8444-555555555555"
	client := &x509.Certificate{Subject: pkix.Name{CommonName: device}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(30 * 24 * time.Hour), BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	leaf, leafPEM, err := issue(client, ec.intermediate, clientKey.Public(), ec.kms)
	if err != nil {
		return nil, err
	}
	files["nas/client.pem"] = append(bytes.Clone(leafPEM), ec.material.Intermediate...)
	files["nas/client.key"], err = keyPEM(clientKey)
	if err != nil {
		return nil, err
	}
	fp := adoption.Digest(leaf.Raw)
	at := domain.Unix(now)
	rec := &domain.DeviceRecord{DeviceID: domain.DeviceID("fleet:1"), Groups: []domain.GroupID{"fleet:1"}, Enrolled: true, ObservedAt: &at}
	snapshot := domain.Snapshot{Version: 2, UpdatedAt: at, Identities: map[string]*domain.DeviceRecord{device: rec}, Certificates: map[string]*domain.DeviceRecord{fp: rec}, HardwareSerials: map[string]*domain.DeviceRecord{}}
	policy, err := json.Marshal(snapshot)
	if err != nil {
		return nil, err
	}
	if _, err = domain.DecodeSnapshot(bytes.NewReader(policy)); err != nil {
		return nil, err
	}
	files["source/etc/freeradius/3.0/device-policy-cache.json"] = policy
	stamp := json.Number(strconv.FormatInt(now.Unix(), 10))
	enrolled, _ := json.Marshal(now.Add(-24 * time.Hour).Format(time.RFC3339))
	binding := []json.RawMessage{json.RawMessage("1"), json.RawMessage(stamp), enrolled}
	trust := adoption.Digest(ec.material.Root)
	state := migration.LegacyCertificateState{Version: 1, Source: "https://fleet.task11.test", Trust: &trust, Hosts: map[string]migration.LegacyCertificateHost{device: {Binding: binding, LastAttempt: stamp, Platform: "darwin", Observation: &migration.LegacyCertificateObservation{Fingerprints: []string{fp}, ObservedAt: stamp, TrustVerified: true, ExpiresAt: map[string]json.Number{fp: json.Number(strconv.FormatInt(leaf.NotAfter.Unix(), 10))}}}}, Commands: []migration.LegacyCommand{{UUID: "task11-retained-command-0001", CreatedAt: stamp, Hosts: map[string][]json.RawMessage{device: binding}}}}
	certificateState, err := json.Marshal(state)
	if err != nil {
		return nil, err
	}
	if _, err = migration.DecodeCertificates(certificateState); err != nil {
		return nil, err
	}
	files["source/var/lib/cloud-8021x/certificate-state.json"] = certificateState
	projection, err := deriveSourceProvenance(policy, certificateState)
	if err != nil {
		return nil, err
	}
	files["source/etc/cloud8021x-task11-source-provenance.json"], err = json.Marshal(projection)
	if err != nil {
		return nil, err
	}

	// This is the ORIGINAL sticky identity guard, not a new deployment marker.
	files["source/var/lib/cloud-8021x/fingerprint-enforced"] = []byte("fingerprint\n")
	class := make([]byte, 32)
	if _, err = rand.Read(class); err != nil {
		return nil, err
	}
	class = []byte(hex.EncodeToString(class))
	files["source/run/radius-accounting-key"] = class
	secret("radius-accounting-class-key", class)
	cloud := struct {
		Contract      *remoteContract              `json:"contract,omitempty"`
		Schema        int                          `json:"schema"`
		ProjectID     string                       `json:"project_id"`
		ProjectNumber string                       `json:"project_number"`
		Secrets       map[string]map[string]string `json:"secrets"`
		Keys          map[string]string            `json:"keys"`
		Routes        []any                        `json:"routes"`
	}{nil, 1, s.Project, "111222333444", secrets, map[string]string{"projects/111222333444/locations/us-central1/keyRings/task11/cryptoKeys/ec/cryptoKeyVersions/1": "ec-kms.pem", "projects/111222333444/locations/us-central1/keyRings/task11/cryptoKeys/rsa/cryptoKeyVersions/1": "rsa-kms.pem"}, []any{}}
	if s.Remote != nil {
		cloud.Contract, err = makeRemoteContract(*s.Remote, now)
		if err != nil {
			return nil, err
		}
	}
	files["api/seed.json"], err = json.Marshal(cloud)
	return files, err
}
