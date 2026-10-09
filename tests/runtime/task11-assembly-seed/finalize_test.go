package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func syntheticOriginal(t *testing.T) (plan, map[string][]byte) {
	t.Helper()
	at := time.Now().UTC().Truncate(time.Second)
	s := seedSpec{Project: "task11-acceptance", ECDNS: "ec.task11.test", RSADNS: "rsa.task11.test", ServerDNS: "radius.task11.test", ECDB: "postgresql://stepca:synthetic@10.203.11.11:5432/stepca?sslmode=verify-full&sslrootcert=/etc/cloud-8021x/postgres-ca.pem", RSADB: "postgresql://stepca:synthetic@10.203.11.11:5432/stepca_rsa?sslmode=verify-full&sslrootcert=/etc/cloud-8021x/postgres-ca.pem", ObservedAt: at, Remote: &remoteSpec{strings.Repeat("a", 64), "Bearer " + strings.Repeat("b", 32), "otlp.us5.datadoghq.com", strings.Repeat("c", 32)}}
	files := map[string][]byte{}
	for _, name := range originalTreeNames() {
		files[name] = []byte("preserved original " + name)
	}
	files["spec.json"], _ = json.Marshal(s)
	files["source/run/radius-accounting-key"] = []byte(strings.Repeat("d", 64))
	cloud := cloudSeed{Schema: 1, ProjectID: s.Project, ProjectNumber: "111222333444", Keys: map[string]string{"projects/111222333444/locations/us-central1/keyRings/task11/cryptoKeys/ec/cryptoKeyVersions/1": "ec-kms.pem", "projects/111222333444/locations/us-central1/keyRings/task11/cryptoKeys/rsa/cryptoKeyVersions/1": "rsa-kms.pem"}, Secrets: map[string]map[string]string{}, Routes: []route{}}
	for _, name := range inheritedSecrets {
		value := []byte("original " + name)
		if name == "radius-accounting-class-key" {
			value = files["source/run/radius-accounting-key"]
		}
		cloud.Secrets["projects/111222333444/secrets/"+name] = map[string]string{"1": base64.StdEncoding.EncodeToString(value)}
	}
	cloud.Contract, _ = json.Marshal(map[string]any{"schema": 1, "gate": "installed-traffic", "application_sha256": s.Remote.ApplicationSHA256, "peers": map[string]any{"10.203.11.21": map[string]string{"role": "green-primary", "phase": "passive"}, "10.203.11.22": map[string]string{"role": "green-secondary", "phase": "passive"}, "10.203.11.31": map[string]string{"role": "original-primary", "phase": "active"}, "10.203.11.32": map[string]string{"role": "original-secondary", "phase": "active"}}, "fleet": map[string]any{"authorization": s.Remote.FleetAuthorization, "hosts": []map[string]any{{"id": 1, "uuid": "11111111-2222-4333-8444-555555555555", "platform": "darwin", "os_version": "15.0", "team_id": 1, "last_mdm_enrolled_at": at.Format(time.RFC3339), "last_enrolled_at": at.Add(-24 * time.Hour).Format(time.RFC3339), "mdm": map[string]any{"enrollment_status": "On"}, "labels": []any{}}}, "commands": []map[string]any{{"command_uuid": "task11-retained-command-0001", "host_id": 1, "host_uuid": "11111111-2222-4333-8444-555555555555", "created_at": at.Format(time.RFC3339), "request_type": "CertificateList", "posts": 0}}}, "otlp": map[string]string{"host": s.Remote.IntakeHost, "api_key": s.Remote.IntakeAPIKey, "authorization": ""}})
	files["api/seed.json"], _ = json.Marshal(cloud)
	for _, kind := range []string{"ec", "rsa"} {
		files["api/"+kind+"-kms.pem"] = []byte("unchanged private KMS key")
	}
	files["original-manifest.json"], _ = originalManifest(files)
	return plan{1, digest(files["api/seed.json"]), digest(files["original-manifest.json"]), at.Add(time.Minute)}, files
}
func TestFinalizeCompletesPrivateInputsWithoutRefreshingOriginal(t *testing.T) {
	p, files := syntheticOriginal(t)
	result, err := finalize(p, files)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"api/tls.pem", "api/tls.key", "api/ca.pem", "postgres/postgres-ca.pem", "postgres/server.pem", "postgres/server.key", "postgres/init.sql", "assembly-input.json"} {
		if len(result.Original[path]) == 0 {
			t.Fatalf("missing finalized private input %s", path)
		}
	}
	for name, raw := range files {
		if name != "api/seed.json" && name != "original-manifest.json" && !bytes.Equal(raw, result.Original[name]) {
			t.Fatalf("original refreshed: %s", name)
		}
	}
	if bytes.Equal(files["original-manifest.json"], result.Original["original-manifest.json"]) {
		t.Fatal("changed seed not rebound to original manifest")
	}
	if err = result.Input.Validate(); err != nil {
		t.Fatal(err)
	}
}
