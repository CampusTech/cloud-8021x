package main

import (
	"errors"
	"net/url"
	"reflect"
	"regexp"
	"strings"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/config"
	seed "github.com/CampusTech/cloud-8021x/tests/runtime/task11-assembly-seed/contract"
)

const database = "cloud8021x_task11_blue"
const migrationDSN = "/run/cloud-8021x-root/postgres-migration-dsn"
const caPath = "/etc/cloud-8021x/postgres-ca.pem"
const sourceConfig = "/etc/cloud8021x-task11-source.yaml"
const installedConfig = "/etc/cloud-8021x/config.yaml"
const planPath = seed.ControlRoot + "/blue-migration.json"

type identity struct {
	UID                               int
	Marker, Hostname, MachineID, PID1 string
}

func validateIdentity(v identity, want string) error {
	if v.UID != 0 || v.Marker != "synthetic-only-v1\n" || v.Hostname != "task11-blue-primary" || !regexp.MustCompile(`^[0-9a-f]{32}$`).MatchString(want) || strings.TrimSpace(v.MachineID) != want || strings.TrimSpace(v.PID1) != "systemd" {
		return errors.New("root enrolled original blue-primary systemd namespace required")
	}
	return nil
}
func validateDSN(raw []byte) error {
	if len(raw) == 0 || len(raw) > 8192 || strings.TrimSpace(string(raw)) != string(raw) {
		return errors.New("bounded exact blue migration credential required")
	}
	u, err := url.Parse(string(raw))
	if err != nil || u.Scheme != "postgresql" || u.Host != "10.203.11.11:5432" || u.Path != "/"+database || u.Fragment != "" || u.Opaque != "" || u.User == nil || u.User.Username() != database+"_migrate" || u.RawQuery != "sslmode=verify-full" {
		return errors.New("fixed private blue migration identity and verified TLS required")
	}
	pass, ok := u.User.Password()
	if !ok || pass == "" {
		return errors.New("private migration credential absent")
	}
	return nil
}
func validateBlueConfig(c config.Config, project, ca string) error {
	if c.Validate() != nil {
		return errors.New("shipping source configuration invalid")
	}
	if c.Hostname != "task11-blue-primary" || c.InstanceID != "radius-primary" || c.Environment != "task11-synthetic" || c.Deployment != (config.Deployment{}) || c.StateTransition != "" || c.Database.Name != database || c.Database.MigrationDSN.File != migrationDSN || c.Database.RuntimeDSN.File != "/run/cloud-8021x/credentials/postgres-runtime-dsn" || c.Database.NativeWriterDSN.File != "/run/cloud-8021x-root/postgres-native-dsn" || c.Database.CAFile != caPath || c.Database.TLSMode != "cloudsql-instance-ca" || c.Database.InstanceCAPEMSHA256 != ca || c.Database.CloudSQLInstance != project+":us-central1:task11-postgres" || c.Bootstrap.Project != project || c.Bootstrap.ProjectNumber != seed.ProjectNumber || c.Bootstrap.RuntimeRole != database+"_runtime" || c.Bootstrap.NativeRole != database+"_native" || c.Bootstrap.LocalAddress != "10.203.11.31" || c.Bootstrap.PeerAddress != "10.203.11.32" || c.Bootstrap.PeerDNS != "task11-blue-secondary" {
		return errors.New("exact original blue database/configuration binding required")
	}
	if c.Policy.IdentityMode != "fingerprint" || c.Policy.AttestedACME.Enabled || c.Paths.InventoryFile != "/etc/freeradius/3.0/device-policy-cache.json" || c.Policy.ClassSigningKey.File != "/run/radius-accounting-key" || c.Listeners.Policy.Address != "127.0.0.1:9082" || c.Network.Discovery.Enabled {
		return errors.New("original source policy boundary differs")
	}
	refs := seed.Credentials(project)
	for i, v := range refs {
		for _, b := range seed.SourceCredentials(project) {
			if b.File == v.File {
				refs[i] = b
			}
		}
	}
	expected := make([]config.BootstrapSecret, 0, len(refs))
	for _, r := range refs {
		expected = append(expected, config.BootstrapSecret{Resource: r.Resource, File: r.File, Owner: r.Owner})
	}
	if !reflect.DeepEqual(c.Bootstrap.Secrets, expected) {
		return errors.New("original blue private credential bindings differ")
	}
	if c.Database.ConnectTimeout > time.Minute || c.Database.QueryTimeout > time.Minute {
		return errors.New("shipping timeout bounds required")
	}
	return nil
}
