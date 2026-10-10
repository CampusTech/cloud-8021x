package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/config"
	"github.com/CampusTech/cloud-8021x/internal/domain"
	"github.com/CampusTech/cloud-8021x/internal/privileged/host"
	"github.com/CampusTech/cloud-8021x/internal/storage/postgres"

	"github.com/CampusTech/cloud-8021x/tests/runtime/task11-assembly-seed/contract"
)

type plan struct {
	Schema          int       `json:"schema"`
	SeedSHA256      string    `json:"seed_sha256"`
	ManifestSHA256  string    `json:"manifest_sha256"`
	CollectionEpoch time.Time `json:"collection_epoch"`
}
type seedSpec struct {
	Project, ECDNS, RSADNS, ServerDNS, ECDB, RSADB string
	ObservedAt                                     time.Time
	Remote                                         *remoteSpec
}
type remoteSpec struct{ ApplicationSHA256, FleetAuthorization, IntakeHost, IntakeAPIKey string }
type route struct {
	Host          string          `json:"host"`
	Method        string          `json:"method"`
	Target        string          `json:"target"`
	Status        int             `json:"status"`
	Response      json.RawMessage `json:"response"`
	BodySHA256    string          `json:"body_sha256"`
	Mutation      bool            `json:"mutation"`
	Authorization string          `json:"authorization"`
}
type cloudSeed struct {
	Contract      json.RawMessage              `json:"contract,omitempty"`
	Schema        int                          `json:"schema"`
	ProjectID     string                       `json:"project_id"`
	ProjectNumber string                       `json:"project_number"`
	Secrets       map[string]map[string]string `json:"secrets"`
	Keys          map[string]string            `json:"keys"`
	Routes        []route                      `json:"routes"`
}
type bundle struct {
	Original, Primitive map[string][]byte
	Input               contract.Input
}

func finalize(p plan, files map[string][]byte) (bundle, error) {
	out := bundle{Original: map[string][]byte{}, Primitive: map[string][]byte{}}
	if err := validateOriginalTree(files); err != nil {
		return out, err
	}
	if p.Schema != 1 || !contract.IsSHA(p.SeedSHA256) || !contract.IsSHA(p.ManifestSHA256) || digest(files["api/seed.json"]) != p.SeedSHA256 || digest(files["original-manifest.json"]) != p.ManifestSHA256 || len(files["assembly-input.json"]) != 0 {
		return out, errors.New("unfinalized original byte pins required")
	}
	original, err := originalManifest(files)
	if err != nil || !bytes.Equal(original, files["original-manifest.json"]) {
		return out, errors.New("original20 manifest differs")
	}
	var spec seedSpec
	var cloud cloudSeed
	if domain.DecodeJSONStrict(files["spec.json"], &spec) != nil || domain.DecodeJSONStrict(files["api/seed.json"], &cloud) != nil || spec.Remote == nil || cloud.Schema != 1 || cloud.ProjectID != spec.Project || cloud.ProjectNumber != contract.ProjectNumber || len(cloud.Routes) != 0 || len(cloud.Secrets) != len(inheritedSecrets) || spec.Remote.IntakeHost != "otlp.us5.datadoghq.com" {
		return out, errors.New("exact original seed specification required")
	}
	var c struct {
		Schema            int             `json:"schema"`
		Gate              string          `json:"gate"`
		ApplicationSHA256 string          `json:"application_sha256"`
		Peers             json.RawMessage `json:"peers"`
		Fleet             struct {
			Authorization string          `json:"authorization"`
			Hosts         json.RawMessage `json:"hosts"`
			Commands      json.RawMessage `json:"commands"`
		} `json:"fleet"`
		OTLP struct {
			Host          string `json:"host"`
			APIKey        string `json:"api_key"`
			Authorization string `json:"authorization"`
		} `json:"otlp"`
	}
	if domain.DecodeJSONStrict(cloud.Contract, &c) != nil || c.Schema != 1 || c.Gate != "installed-traffic" || c.ApplicationSHA256 != spec.Remote.ApplicationSHA256 || !contract.IsSHA(c.ApplicationSHA256) || c.Fleet.Authorization != spec.Remote.FleetAuthorization || c.OTLP.Host != spec.Remote.IntakeHost || c.OTLP.APIKey != spec.Remote.IntakeAPIKey || !strings.HasPrefix(c.Fleet.Authorization, "Bearer ") {
		return out, errors.New("original installed remote contract differs")
	}
	for _, name := range inheritedSecrets {
		v := cloud.Secrets["projects/"+contract.ProjectNumber+"/secrets/"+name]
		b, e := base64.StdEncoding.DecodeString(v["1"])
		if len(v) != 1 || e != nil || len(b) == 0 {
			return out, errors.New("original immutable secret absent")
		}
	}
	class, _ := base64.StdEncoding.DecodeString(cloud.Secrets["projects/"+contract.ProjectNumber+"/secrets/radius-accounting-class-key"]["1"])
	if !bytes.Equal(class, files["source/run/radius-accounting-key"]) || len(class) < 32 || len(class) > 4096 {
		return out, errors.New("inherited Class identity differs")
	}
	if _, err = host.CollectorEnvironment([]byte(spec.Remote.IntakeAPIKey), host.Accounts{}); err != nil {
		return out, err
	}
	for path, b := range files {
		out.Original[path] = bytes.Clone(b)
	}
	values := map[string][]byte{"radius-accounting-class-key": class, "stepca-dsn": []byte(spec.ECDB), "stepca-rsa-dsn": []byte(spec.RSADB), "fleet-observer-token": []byte(strings.TrimPrefix(spec.Remote.FleetAuthorization, "Bearer ")), "fleet-maintainer-token": []byte(strings.TrimPrefix(spec.Remote.FleetAuthorization, "Bearer ")), "datadog-api-key": []byte(spec.Remote.IntakeAPIKey)}
	pg, err := postgresFiles(spec, values)
	if err != nil {
		return out, err
	}
	for path, b := range pg {
		out.Original[path] = b
	}
	for _, set := range []struct{ database, prefix string }{{contract.Database, "postgres-"}, {"cloud8021x_task11_blue", "postgres-blue-"}} {
		cfg := config.Database{Name: set.database, CAFile: "/etc/cloud-8021x/postgres-ca.pem", TLSMode: "cloudsql-instance-ca", CloudSQLInstance: spec.Project + ":us-central1:task11-postgres", InstanceCAPEMSHA256: digest(pg["postgres/postgres-ca.pem"]), ConnectTimeout: 5 * time.Second, QueryTimeout: 5 * time.Second}
		for _, kind := range []string{"runtime", "migration", "native"} {
			if _, e := postgres.NativeConninfoWithCA(string(values[set.prefix+kind+"-dsn"]), cfg, pg["postgres/postgres-ca.pem"]); e != nil {
				return out, e
			}
		}
	}
	for _, ref := range append(contract.Credentials(spec.Project), contract.SourceCredentials(spec.Project)...) {
		if len(values[ref.ID]) == 0 {
			v, e := randomText()
			if e != nil {
				return out, e
			}
			if ref.ID == "radius-task11-secret" {
				v = "task11-" + v
			}
			values[ref.ID] = []byte(v)
		}
		resource := "projects/" + contract.ProjectNumber + "/secrets/" + ref.ID
		if ref.ID != "radius-accounting-class-key" {
			if cloud.Secrets[resource] != nil {
				return out, errors.New("credential would replace original secret")
			}
			cloud.Secrets[resource] = map[string]string{"1": base64.StdEncoding.EncodeToString(values[ref.ID])}
		}
	}
	if err = addNASInputs(out.Original, values); err != nil {
		return out, err
	}
	ca, cert, key, err := tlsIdentity([]string{"secretmanager.googleapis.com", "cloudkms.googleapis.com", "sqladmin.googleapis.com", "fleet.task11.test", spec.Remote.IntakeHost, "otlp.task11.test", "unifi.task11.test"}, nil, spec.ObservedAt)
	if err != nil {
		return out, err
	}
	out.Original["api/ca.pem"], out.Original["api/tls.pem"], out.Original["api/tls.key"] = ca, cert, key
	cloud.Routes = staticRoutes(spec.Project, out.Original["postgres/postgres-ca.pem"])
	out.Original["api/seed.json"], err = json.Marshal(cloud)
	if err != nil {
		return out, err
	}
	for _, role := range []string{"blue-primary", "blue-secondary", "green-primary", "green-secondary"} {
		metadata, _ := json.Marshal(cloudSeed{Schema: 1, ProjectID: spec.Project, ProjectNumber: contract.ProjectNumber, Secrets: map[string]map[string]string{}, Keys: map[string]string{}, Routes: []route{}})
		out.Original["metadata/task11-"+role+"/seed.json"] = metadata
	}
	out.Original["original-manifest.json"], err = originalManifest(out.Original)
	if err != nil {
		return out, err
	}
	out.Input = contract.Input{Schema: 1, Project: spec.Project, ProjectNumber: contract.ProjectNumber, SQLInstance: spec.Project + ":us-central1:task11-postgres", ECDNS: spec.ECDNS, RSADNS: spec.RSADNS, ServerDNS: spec.ServerDNS, ObservedAt: spec.ObservedAt, CollectionEpoch: p.CollectionEpoch, DatadogSite: "us5.datadoghq.com", PostgresCA: contract.FilePin{Path: "postgres/postgres-ca.pem", SHA256: digest(pg["postgres/postgres-ca.pem"])}, APICA: contract.FilePin{Path: "api/ca.pem", SHA256: digest(ca)}, InstalledSeedSHA256: digest(out.Original["api/seed.json"]), OriginalManifestSHA256: digest(out.Original["original-manifest.json"]), OriginalStateSHA256: digest(files["source/var/lib/cloud-8021x/certificate-state.json"]), SourceCredentials: contract.SourceCredentials(spec.Project), Credentials: contract.Credentials(spec.Project), Files: map[string]string{}}
	for path, b := range out.Original {
		out.Input.Files[path] = digest(b)
	}
	if err = out.Input.Validate(); err != nil {
		return out, err
	}
	out.Original["assembly-input.json"], err = json.Marshal(out.Input)
	if err != nil {
		return out, err
	}
	out.Primitive, err = primitiveInputs(spec, cloud, ca, cert, key)
	return out, err
}
func staticRoutes(project string, pgCA []byte) []route {
	response, _ := json.Marshal(map[string]any{"connectionName": project + ":us-central1:task11-postgres", "serverCaMode": "GOOGLE_MANAGED_INTERNAL_CA", "serverCaCert": map[string]string{"cert": string(pgCA)}})
	out := []route{{Host: "sqladmin.googleapis.com", Method: "GET", Target: "/sql/v1beta4/projects/" + project + "/instances/task11-postgres", Status: 200, Response: response, BodySHA256: digest(nil), Authorization: "Bearer task11-synthetic-token-not-a-cloud-credential"}}
	base := "/v1/connector/consoles/task11-console/proxy/network/integration/v1/sites"
	for _, item := range []struct{ path, body string }{{"", `{"data":[{"id":"task11-site","name":"N/A"}],"offset":0,"count":1,"totalCount":1}`}, {"/task11-site/devices", `{"data":[],"offset":0,"count":0,"totalCount":0}`}, {"/task11-site/networks", `{"data":[],"offset":0,"count":0,"totalCount":0}`}} {
		out = append(out, route{Host: "unifi.task11.test", Method: "GET", Target: base + item.path + "?limit=200&offset=0", Status: 200, Response: json.RawMessage(item.body), BodySHA256: digest(nil)})
	}
	return out
}
