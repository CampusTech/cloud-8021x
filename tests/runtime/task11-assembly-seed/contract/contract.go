// Package contract describes reviewed synthetic assembly inputs, never installed readiness.
package contract

import (
	"errors"
	"path"
	"reflect"
	"regexp"
	"strings"
	"time"
)

const ControlRoot = "/var/lib/cloud8021x-task11/control"
const OriginalRoot = ControlRoot + "/original-seed"
const Database = "cloud8021x_task11_green"
const ProjectNumber = "111222333444"

type FilePin struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}
type Credential struct {
	ID       string `json:"id"`
	Resource string `json:"resource"`
	File     string `json:"file"`
	Owner    string `json:"owner"`
}

// Paths are relative to the finalized original tree. All pins are exact bytes.
// Primitive execution results and expected pins are separate enrollment inputs.
type Input struct {
	Schema                 int               `json:"schema"`
	Project                string            `json:"project"`
	ProjectNumber          string            `json:"project_number"`
	SQLInstance            string            `json:"sql_instance"`
	ECDNS                  string            `json:"ec_dns"`
	RSADNS                 string            `json:"rsa_dns"`
	ServerDNS              string            `json:"server_dns"`
	ObservedAt             time.Time         `json:"observed_at"`
	CollectionEpoch        time.Time         `json:"collection_epoch"`
	DatadogSite            string            `json:"datadog_site"`
	PostgresCA             FilePin           `json:"postgres_ca"`
	APICA                  FilePin           `json:"api_ca"`
	InstalledSeedSHA256    string            `json:"installed_seed_sha256"`
	OriginalManifestSHA256 string            `json:"original_manifest_sha256"`
	OriginalStateSHA256    string            `json:"original_state_sha256"`
	SourceCredentials      []Credential      `json:"source_credentials"`
	Credentials            []Credential      `json:"credentials"`
	Files                  map[string]string `json:"files"`
}

func Credentials(project string) []Credential {
	var out []Credential
	for _, group := range []struct {
		owner, dir string
		ids        []string
	}{
		{"runtime", "/run/cloud-8021x/credentials", []string{"postgres-runtime-dsn", "policy-token", "peer-health", "fleet-observer-token", "fleet-maintainer-token", "scep-challenge-key", "scep-broker-token", "radius-accounting-class-key", "unifi-token"}},
		{"root", "/run/cloud-8021x-root", []string{"postgres-migration-dsn", "postgres-native-dsn", "stepca-dsn", "stepca-rsa-dsn", "radius-task11-secret"}},
		{"collector", "/run/cloud-8021x-collector", []string{"datadog-api-key"}},
	} {
		for _, id := range group.ids {
			base := id
			if id == "radius-accounting-class-key" {
				base = "accounting-class-key"
			}
			out = append(out, Credential{id, "projects/" + project + "/secrets/" + id, group.dir + "/" + base, group.owner})
		}
	}
	return out
}
func SourceCredentials(project string) []Credential {
	return []Credential{{"postgres-blue-runtime-dsn", "projects/" + project + "/secrets/postgres-blue-runtime-dsn", "/run/cloud-8021x/credentials/postgres-runtime-dsn", "runtime"}, {"postgres-blue-migration-dsn", "projects/" + project + "/secrets/postgres-blue-migration-dsn", "/run/cloud-8021x-root/postgres-migration-dsn", "root"}, {"postgres-blue-native-dsn", "projects/" + project + "/secrets/postgres-blue-native-dsn", "/run/cloud-8021x-root/postgres-native-dsn", "root"}}
}
func IsSHA(s string) bool { return regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(s) }
func (i Input) Validate() error {
	if i.Schema != 1 || !regexp.MustCompile(`^task11-[a-z0-9-]{1,22}$`).MatchString(i.Project) || i.ProjectNumber != ProjectNumber || i.SQLInstance != i.Project+":us-central1:task11-postgres" {
		return errors.New("exact synthetic assembly identity required")
	}
	if i.ObservedAt.IsZero() || i.ObservedAt.Nanosecond() != 0 || i.ObservedAt.Location() != time.UTC || i.CollectionEpoch.Before(i.ObservedAt) || i.CollectionEpoch.Nanosecond() != 0 || i.CollectionEpoch.Location() != time.UTC {
		return errors.New("immutable UTC second observation and explicit epoch required")
	}
	for _, name := range []string{i.ECDNS, i.RSADNS, i.ServerDNS} {
		if !regexp.MustCompile(`^[a-z0-9-]+\.task11\.test$`).MatchString(name) {
			return errors.New("bounded synthetic certificate DNS required")
		}
	}
	if i.ECDNS == i.RSADNS || i.DatadogSite != "us5.datadoghq.com" || (!reflect.DeepEqual(i.Credentials, Credentials(i.Project)) || !reflect.DeepEqual(i.SourceCredentials, SourceCredentials(i.Project))) {
		return errors.New("closed credential and endpoint contract differs")
	}
	for _, pin := range []string{i.InstalledSeedSHA256, i.OriginalManifestSHA256, i.OriginalStateSHA256, i.PostgresCA.SHA256, i.APICA.SHA256} {
		if !IsSHA(pin) {
			return errors.New("exact finalized byte pins required")
		}
	}
	if i.PostgresCA.Path != "postgres/postgres-ca.pem" || i.APICA.Path != "api/ca.pem" || i.Files[i.PostgresCA.Path] != i.PostgresCA.SHA256 || i.Files[i.APICA.Path] != i.APICA.SHA256 || i.Files["api/seed.json"] != i.InstalledSeedSHA256 || i.Files["original-manifest.json"] != i.OriginalManifestSHA256 || i.Files["source/var/lib/cloud-8021x/certificate-state.json"] != i.OriginalStateSHA256 {
		return errors.New("finalized file pins are inconsistent")
	}
	if len(i.Files) < 25 || len(i.Files) > 80 {
		return errors.New("bounded complete assembly inventory required")
	}
	for name, sha := range i.Files {
		if path.IsAbs(name) || path.Clean(name) != name || strings.HasPrefix(name, "../") || name == "assembly-input.json" || !IsSHA(sha) {
			return errors.New("invalid pinned relative file")
		}
	}
	return nil
}
