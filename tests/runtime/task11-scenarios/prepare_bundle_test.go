package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/migration"

	"github.com/CampusTech/cloud-8021x/internal/config"
	"github.com/CampusTech/cloud-8021x/internal/domain"
	seed "github.com/CampusTech/cloud-8021x/tests/runtime/task11-assembly-seed/contract"
	"gopkg.in/yaml.v3"
)

func producerFixture(t *testing.T) producerInputs {
	t.Helper()
	ec := pureECFixture(t)
	rsa := pureSCEPFixture(t)
	files := map[string][]byte{}
	for _, n := range producerOriginalNames {
		files[n] = []byte("synthetic preserved " + n)
	}
	material := map[string][]byte{"eap.conf": fixedNASConfig(), "radius-secret": []byte("task11-" + strings.Repeat("r", 64)), "broker-token": []byte(strings.Repeat("b", 64)), "class-key": []byte(strings.Repeat("c", 64)), "client.pem": ec.clientPEM, "client.key": ec.keyPEM, "ec-root.pem": ec.rootPEM, "ec-intermediate.pem": ec.intermediatePEM, "rsa-root.pem": pemCertificate(rsa.root), "rsa-intermediate.pem": pemCertificate(rsa.intermediate), "broker.crt": pureTrustPEM(t, false, "localhost")}
	keyDER, e := x509.MarshalPKCS8PrivateKey(rsa.clientKey)
	if e != nil {
		t.Fatal(e)
	}
	material["scep-client.key"] = pemPrivateKey(keyDER)
	for name, path := range producerMaterialPaths {
		files[path] = material[name]
	}
	rejectKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rejectDER, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{SerialNumber: big.NewInt(5), Subject: pkix.Name{CommonName: rejectedDevice}, NotBefore: ec.now.Add(-time.Minute), NotAfter: ec.now.Add(time.Hour), BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}, ec.intermediate, rejectKey.Public(), ec.intermediateKey)
	if err != nil {
		t.Fatal(err)
	}
	rejectLeaf, err := x509.ParseCertificate(rejectDER)
	if err != nil {
		t.Fatal(err)
	}
	rejectPrivate, err := x509.MarshalPKCS8PrivateKey(rejectKey)
	if err != nil {
		t.Fatal(err)
	}
	files["nas/reject-client.pem"] = append(pemCertificate(rejectLeaf), ec.intermediatePEM...)
	files["nas/reject-client.key"] = pemPrivateKey(rejectPrivate)
	files["nas/reject-eap.conf"] = fixedRejectNASConfig()
	cloud := producerCloud{Schema: 1, ProjectID: "task11-acceptance", ProjectNumber: seed.ProjectNumber, Secrets: map[string]map[string]string{}, Keys: map[string]string{}, Routes: []json.RawMessage{}}
	for name, b := range map[string][]byte{"radius-task11-secret": material["radius-secret"], "scep-broker-token": material["broker-token"], "smallstep-rsa-scep-decrypter-cert": pemCertificate(rsa.decrypter), "radius-accounting-class-key": material["class-key"]} {
		cloud.Secrets["projects/"+seed.ProjectNumber+"/secrets/"+name] = map[string]string{"1": base64.StdEncoding.EncodeToString(b)}
	}
	files["api/seed.json"], _ = json.Marshal(cloud)
	at := time.Now().UTC().Truncate(time.Second)
	spec := producerSpec{Project: cloud.ProjectID, ECDNS: "ec.task11.test", RSADNS: "rsa.task11.test", ServerDNS: nativeServerDNS, Remote: &struct{ ApplicationSHA256, FleetAuthorization, IntakeHost, IntakeAPIKey string }{strings.Repeat("a", 64), "Bearer synthetic", "otlp.us5.datadoghq.com", "synthetic"}}
	spec.ObservedAt = at
	files["spec.json"], _ = json.Marshal(spec)
	seen := domain.Unix(at)
	rec := &domain.DeviceRecord{DeviceID: "fleet:1", Groups: []domain.GroupID{"fleet:1"}, Enrolled: true, ObservedAt: &seen}
	snapshot := domain.Snapshot{Version: 2, UpdatedAt: seen, Identities: map[string]*domain.DeviceRecord{ec.old.Subject.CommonName: rec}, Certificates: map[string]*domain.DeviceRecord{digestBytes(ec.old.Raw): rec}, HardwareSerials: map[string]*domain.DeviceRecord{}}
	files["source/etc/freeradius/3.0/device-policy-cache.json"], _ = json.Marshal(snapshot)
	stamp := json.Number(strconv.FormatInt(at.Unix(), 10))
	enrolledAt, _ := json.Marshal(at.Add(-time.Hour).Format(time.RFC3339))
	binding := []json.RawMessage{json.RawMessage("1"), json.RawMessage(stamp), enrolledAt}
	trust := digestBytes(ec.rootPEM)
	state := migration.LegacyCertificateState{Version: 1, Source: "https://fleet.task11.test", Trust: &trust, Hosts: map[string]migration.LegacyCertificateHost{ec.old.Subject.CommonName: {Binding: binding, Platform: "darwin", LastAttempt: stamp, Observation: &migration.LegacyCertificateObservation{Fingerprints: []string{digestBytes(ec.old.Raw)}, ObservedAt: stamp, TrustVerified: true}}}, Commands: []migration.LegacyCommand{}}
	files["source/var/lib/cloud-8021x/certificate-state.json"], _ = json.Marshal(state)
	// Match the original preserved RADIUS server SAN using an actual signed leaf.
	files["source/etc/freeradius/3.0/certs/server.pem"] = pureTrustPEM(t, false, nativeServerDNS)
	manifest := producerManifest{Schema: 1, Files: map[string]string{}}
	for _, n := range producerOriginalNames {
		manifest.Files[n] = digestBytes(files[n])
	}
	rawManifest, _ := json.Marshal(manifest)
	files["original-manifest.json"] = rawManifest
	files["postgres/postgres-ca.pem"] = ec.rootPEM
	files["api/ca.pem"] = ec.rootPEM
	i := seed.Input{Schema: 1, Project: cloud.ProjectID, ProjectNumber: seed.ProjectNumber, SQLInstance: cloud.ProjectID + ":us-central1:task11-postgres", ECDNS: spec.ECDNS, RSADNS: spec.RSADNS, ServerDNS: spec.ServerDNS, ObservedAt: at, CollectionEpoch: at.Add(time.Minute), DatadogSite: "us5.datadoghq.com", PostgresCA: seed.FilePin{Path: "postgres/postgres-ca.pem", SHA256: digestBytes(ec.rootPEM)}, APICA: seed.FilePin{Path: "api/ca.pem", SHA256: digestBytes(ec.rootPEM)}, InstalledSeedSHA256: digestBytes(files["api/seed.json"]), OriginalManifestSHA256: digestBytes(rawManifest), OriginalStateSHA256: digestBytes(files["source/var/lib/cloud-8021x/certificate-state.json"]), Credentials: seed.Credentials(cloud.ProjectID), SourceCredentials: seed.SourceCredentials(cloud.ProjectID), Files: map[string]string{}}
	for name, b := range files {
		i.Files[name] = digestBytes(b)
	}
	in := producerInputs{Manifest: rawManifest, Files: files, Configs: map[string][]byte{}}
	in.Input, _ = json.Marshal(i)
	enrolled := producerEnrollment{Schema: 1, ApplicationSHA256: spec.Remote.ApplicationSHA256, ControllerSHA256: strings.Repeat("d", 64), Nodes: map[string]struct{ MachineID, Hostname, Pin, ConfigSHA256 string }{}}
	enrolled.Passive.OriginalSeedSHA256 = i.OriginalManifestSHA256
	enrolled.Cloud.InstalledSeedSHA256 = i.InstalledSeedSHA256
	enrolled.Cloud.OriginalStateSHA256 = i.OriginalStateSHA256
	pf := producerPlatform{Schema: 1, InputSHA256: digestBytes(in.Input), CandidateSHA256: strings.Repeat("f", 64), Helpers: map[string]producerPin{}}
	for _, h := range []string{"task11-acceptance", "task11-passive-audit", "task11-cloud-contract", "task11-assembly-seed", "task11-blue-migration", "task11-systemd-fixture", "task11-scenarios"} {
		pf.Helpers[h] = producerPin{Path: "/usr/local/libexec/" + h, SHA256: strings.Repeat("d", 64)}
	}
	for x, n := range []string{"blue-primary", "blue-secondary", "green-primary", "green-secondary"} {
		c := config.Defaults()
		c.SchemaVersion = 1
		c.Hostname = "task11-green-" + strings.TrimPrefix(strings.TrimPrefix(n, "blue-"), "green-")
		c.InstanceID = "radius-" + strings.TrimPrefix(strings.TrimPrefix(n, "blue-"), "green-")
		c.Database.RuntimeDSN = config.SecretRef{File: "/run/runtime"}
		c.Database.MigrationDSN = config.SecretRef{File: "/run/migration"}
		c.Database.NativeWriterDSN = config.SecretRef{File: "/run/native"}
		c.Database.CAFile = "/etc/cloud-8021x/postgres-ca.pem"
		c.Inventory.Fleet.ManagedCertificates = true
		c.Network.Providers = []config.NetworkProvider{{ID: "task11-unifi", Kind: "unifi", BaseURL: "https://unifi.task11.test/v1", Credential: config.SecretRef{File: "/run/unifi"}, Scopes: []string{"task11-site"}, ConsoleID: "task11-console", Timeout: 5 * time.Second}}
		c.Network.Locations = []config.Location{{ID: "task11", ProviderID: "task11-unifi", SiteID: "task11-site", VLANEnabled: true}}
		c.Bootstrap.ServerDNS = nativeServerDNS
		c.Bootstrap.ECDNS = spec.ECDNS
		c.Bootstrap.RSADNS = spec.RSADNS
		c.CA.URL = "https://" + spec.ECDNS + ":8443"
		c.Policy.ClassSigningKey = config.SecretRef{File: "/run/cloud-8021x/credentials/accounting-class-key"}
		c.Policy.Rules = []config.VLANRule{{GroupID: "fleet:1", LocationID: "task11", VLAN: 120}}
		c.RadiusClients = []config.RadiusClient{{ID: "task11-nas", LocationID: "task11", CIDRs: []string{"10.203.11.40/32"}, Secret: config.SecretRef{File: "/run/cloud-8021x-root/radius-task11-secret"}, Medium: "wifi", SignalingProfile: "unifi-numeric"}}
		c.Listeners.Broker = config.BrokerListener{Enabled: true, Address: "0.0.0.0:9081", CertFile: "/etc/webhook.crt", KeyFile: config.SecretRef{File: "/run/webhook.key"}, Username: "fleet", Token: config.SecretRef{File: "/run/cloud-8021x/credentials/scep-broker-token"}, SigningKey: config.SecretRef{File: "/run/challenge"}, SCEPURL: "https://" + spec.RSADNS + ":8444/scep/wifi-scep", Provisioner: "wifi-scep"}
		c.StateTransition = strings.Repeat("b", 64)
		c.Database.Name = seed.Database
		c.Deployment = config.Deployment{SourcePrimaryKey: strings.Repeat("1", 64), SourceSecondaryKey: strings.Repeat("2", 64), DestinationPrimaryKey: strings.Repeat("3", 64), DestinationSecondaryKey: strings.Repeat("4", 64), Mode: "parallel", ID: "task11-green", Instance: c.Hostname, SourceID: "task11-blue", SourcePrimary: "task11-blue-primary", SourceSecondary: "task11-blue-secondary", CollectionEpoch: i.CollectionEpoch}
		if err := c.Validate(); err != nil {
			t.Fatalf("pure config setup %s: %v", n, err)
		}
		b, err := yaml.Marshal(c)
		if err != nil {
			t.Fatal(err)
		}
		in.Configs[n] = b
		names := []string{"c11-bp", "c11-bs", "c11-gp", "c11-gs"}
		ips := []string{"10.203.11.31", "10.203.11.32", "10.203.11.21", "10.203.11.22"}
		node := producerNode{Name: n, Machine: "task11-" + n, Root: "/var/lib/cloud8021x-task11/roots/task11-" + n, Namespace: names[x], Address: ips[x], MachineID: strings.Repeat(string(rune('1'+x)), 32), ConfigSHA256: digestBytes(b)}
		pf.Nodes = append(pf.Nodes, node)
		enrolled.Nodes[n] = struct{ MachineID, Hostname, Pin, ConfigSHA256 string }{node.MachineID, node.Machine, strings.Repeat(string(rune('1'+x)), 64), node.ConfigSHA256}
	}
	pf.Auxiliary = []producerAux{{"api", "/var/lib/cloud8021x-task11/aux/api", "c11-api", "10.203.11.10"}, {"pg", "/var/lib/cloud8021x-task11/aux/pg", "c11-pg", "10.203.11.11"}, {"nas", "/var/lib/cloud8021x-task11/aux/nas", "c11-nas", "10.203.11.40"}}
	pp := map[string]any{"Schema": 1, "InputSHA256": pf.InputSHA256, "CandidateSHA256": pf.CandidateSHA256, "ApplicationSHA256": enrolled.ApplicationSHA256, "ControllerSHA256": enrolled.ControllerSHA256, "Helpers": map[string]producerPin{}}
	for h, pin := range pf.Helpers {
		pin.Path = outerControl + "/public/" + h
		pp["Helpers"].(map[string]producerPin)[h] = pin
	}
	in.PlatformPlan, _ = json.Marshal(pp)
	pf.PlanSHA256 = digestBytes(in.PlatformPlan)
	in.Platform, _ = json.Marshal(pf)
	in.Enrollment, _ = json.Marshal(enrolled)
	return in
}
func TestPrepareProducesTenPlansFromPreservedInputs(t *testing.T) {
	in := producerFixture(t)
	b, e := prepareNASBundle(in)
	if e != nil {
		t.Fatal(e)
	}
	if len(b.Materials) != 16 || len(b.Plans) != 10 {
		t.Fatal("closed producer set missing")
	}
	for name, raw := range b.Plans {
		p, e := decodeNASPlan(raw, digestBytes(raw))
		if e != nil {
			t.Fatal(e)
		}
		if len(p.Materials) != 13 {
			t.Fatal("positive/base thirteen material contract changed")
		}
		if p.Scenario.Case+".json" != name || p.ClientLeafSHA256 == "" || p.Scenario.Session != "task11-"+p.Scenario.Case {
			t.Fatal("plan identity differs")
		}
		if !bytes.Equal(in.Files["nas/client.pem"], b.Materials["client.pem"]) || !bytes.Equal(in.Files["nas/client.key"], b.Materials["client.key"]) {
			t.Fatal("original EC rewritten")
		}
	}
}
