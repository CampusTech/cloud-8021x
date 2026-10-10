package main

import (
	"time"

	"github.com/CampusTech/cloud-8021x/internal/accounting"
)

type plannedEvent struct {
	Status   int    `json:"status"`
	Duration uint32 `json:"duration"`
	Upload   uint64 `json:"upload"`
	Download uint64 `json:"download"`
}
type scenarioPlan struct {
	Schema             int            `json:"schema"`
	Scenario           string         `json:"scenario"`
	Case               string         `json:"case"`
	PlatformSHA256     string         `json:"platform_sha256"`
	EnrollmentSHA256   string         `json:"enrollment_sha256"`
	ApplicationSHA256  string         `json:"application_sha256"`
	SelfSHA256         string         `json:"self_sha256"`
	OriginalSeedSHA256 string         `json:"original_seed_sha256"`
	CollectionEpoch    time.Time      `json:"collection_epoch"`
	Node               string         `json:"node"`
	Target             string         `json:"target"`
	Namespace          string         `json:"namespace"`
	Machine            string         `json:"machine"`
	NAS                string         `json:"nas"`
	NASNamespace       string         `json:"nas_namespace"`
	Session            string         `json:"session"`
	Events             []plannedEvent `json:"events"`
	OutageSeconds      int            `json:"outage_seconds"`
}
type liveIdentity struct {
	Machine, Root, MachineID, BootID, ConfigSHA256, ApplicationSHA256 string
	Leader                                                            int
	StartTicks, Namespace, ObservedSequence                           uint64
}
type attemptRecord struct {
	Schema                       int
	Scenario, PlanSHA256, Status string
}
type expectations struct {
	Events                    []accounting.Event
	Intervals                 []accounting.Interval
	Upload, Download, Seconds uint64
}
type continuity struct {
	Machine, MachineID, Root, BootID, ApplicationSHA256, ConfigSHA256, CollectorBacking, CollectorFilesystem, CollectorOptions, Epoch, Deployment string
	Leader                                                                                                                                        int
	StartTicks, CollectorBytes, CollectorDevice, CollectorInode                                                                                   uint64
	WorkersActive                                                                                                                                 bool
}
type accountingEvidence struct {
	PacketACKs                                                  int
	LedgerVerified                                              bool
	ControllerVerifiedCloudSHA256, IndependentExpectationSHA256 string
}
type caClientPlan struct {
	Blue                    string `json:"peer"`
	DNS                     string `json:"dns"`
	Provisioner             string `json:"provisioner"`
	RootSHA256              string `json:"root_sha256"`
	IntermediateSHA256      string `json:"intermediate_sha256"`
	DecrypterSHA256         string `json:"decrypter_sha256"`
	BrokerCertificateSHA256 string `json:"broker_certificate_sha256"`
	BrokerTLSName           string `json:"broker_tls_name"`
	BrokerTokenSHA256       string `json:"broker_token_sha256"`
}
