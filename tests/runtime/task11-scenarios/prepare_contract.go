package main

import (
	"encoding/json"
	"time"

	"github.com/CampusTech/cloud-8021x/tests/runtime/task11-assembly-seed/contract"
)

type producerPin struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}
type producerNode struct {
	Name         string `json:"name"`
	Machine      string `json:"machine"`
	Root         string `json:"root"`
	Namespace    string `json:"namespace"`
	Address      string `json:"address"`
	MachineID    string `json:"machine_id"`
	ConfigSHA256 string `json:"config_sha256"`
}
type producerAux struct {
	Name      string `json:"name"`
	Root      string `json:"root"`
	Namespace string `json:"namespace"`
	Address   string `json:"address"`
}
type producerPlatform struct {
	Schema          int                    `json:"schema"`
	PlanSHA256      string                 `json:"plan_sha256"`
	InputSHA256     string                 `json:"input_sha256"`
	CandidateSHA256 string                 `json:"candidate_sha256"`
	Nodes           []producerNode         `json:"nodes"`
	Auxiliary       []producerAux          `json:"auxiliary"`
	Helpers         map[string]producerPin `json:"helpers"`
}
type producerEnrollment struct {
	Cloud   struct{ HelperSHA256, PrimitiveSeedSHA256, PrimitiveExpectedSHA256, InstalledSeedSHA256, OriginalStateSHA256 string }
	Passive struct {
		ObserverSHA256, ObserverSourceSHA256, CloudSourceSHA256, ApplicationSourceSHA, OriginalSeedSHA256 string
		Manifests                                                                                         map[string]string
	}
	Schema                              int
	ApplicationSHA256, ControllerSHA256 string
	Nodes                               map[string]struct{ MachineID, Hostname, Pin, ConfigSHA256 string }
}
type producerCloud struct {
	Schema        int                          `json:"schema"`
	ProjectID     string                       `json:"project_id"`
	ProjectNumber string                       `json:"project_number"`
	Secrets       map[string]map[string]string `json:"secrets"`
	Keys          map[string]string            `json:"keys"`
	Routes        []json.RawMessage            `json:"routes"`
	Contract      json.RawMessage              `json:"contract,omitempty"`
}
type producerManifest struct {
	Schema int
	Files  map[string]string
}
type producerSpec struct {
	Project, ECDNS, RSADNS, ServerDNS, ECDB, RSADB string
	ObservedAt                                     time.Time
	Remote                                         *struct{ ApplicationSHA256, FleetAuthorization, IntakeHost, IntakeAPIKey string }
}
type producerValidated struct {
	Input      contract.Input
	Platform   producerPlatform
	Enrollment producerEnrollment
	Spec       producerSpec
}

var producerCases = []string{"native-accounting", "eap-unenrolled", "ongoing-interim", "ongoing-stop", "duplicate-pair", "ha-primary", "postgres-outage", "business-outage", "ca-ec-continuity", "ca-rsa-continuity"}
var producerOriginalNames = []string{"spec.json", "api/seed.json", "source/etc/step-ca/certs/root_ca.crt", "source/etc/step-ca/certs/intermediate_ca.crt", "source/etc/step-ca/config/ca.json", "source/etc/step-ca/templates/x509/wifi-acme.tpl", "source/etc/step-ca-rsa/certs/root_ca.crt", "source/etc/step-ca-rsa/certs/intermediate_ca.crt", "source/etc/step-ca-rsa/config/ca.json", "source/etc/step-ca-rsa/templates/x509/wifi-scep.tpl", "source/etc/acme-authz-webhook/server.crt", "source/etc/acme-authz-webhook/server.key", "source/etc/freeradius/3.0/certs/server.pem", "source/etc/freeradius/3.0/certs/server-key.pem", "source/etc/freeradius/3.0/certs/ca.pem", "source/etc/freeradius/3.0/device-policy-cache.json", "source/var/lib/cloud-8021x/certificate-state.json", "source/etc/cloud8021x-task11-source-provenance.json", "source/var/lib/cloud-8021x/fingerprint-enforced", "source/run/radius-accounting-key"}
var producerRejectMaterialPaths = map[string]string{"reject-eap.conf": "nas/reject-eap.conf", "reject-client.pem": "nas/reject-client.pem", "reject-client.key": "nas/reject-client.key"}
var producerMaterialPaths = map[string]string{"eap.conf": "nas/eap.conf", "radius-secret": "nas/radius-secret", "class-key": "source/run/radius-accounting-key", "client.pem": "nas/client.pem", "client.key": "nas/client.key", "ec-root.pem": "source/etc/step-ca/certs/root_ca.crt", "ec-intermediate.pem": "source/etc/step-ca/certs/intermediate_ca.crt", "rsa-root.pem": "source/etc/step-ca-rsa/certs/root_ca.crt", "rsa-intermediate.pem": "source/etc/step-ca-rsa/certs/intermediate_ca.crt", "broker.crt": "source/etc/acme-authz-webhook/server.crt", "broker-token": "nas/broker-token", "scep-client.key": "nas/scep-client.key"}
