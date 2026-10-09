// Package contract is the development-only fixed passive observer wire contract.
package contract

import "time"

const Executable = "/usr/local/libexec/task11-passive-audit"
const SeedManifest = "/etc/cloud8021x-task11-passive-seed.json"
const MaxRequestBytes = 16 << 10
const MaxResultBytes = 256 << 10

var NamespaceNames = []string{"mnt", "pid", "uts", "net", "cgroup"}
var Services = []string{"cloud-8021x.service", "freeradius.service", "step-ca.service", "step-ca-rsa.service", "cloud-8021x-renew.service", "cloud-8021x-sources.service", "datadog-agent.service", "datadog-agent-ddot.service"}
var Timers = []string{"cloud-8021x-renew.timer", "cloud-8021x-sources.timer"}
var Slots = []string{"ec-root", "ec-intermediate", "ec-decrypter", "ec-decrypter-key", "ec-config", "ec-template", "rsa-root", "rsa-intermediate", "rsa-decrypter", "rsa-decrypter-key", "rsa-config", "rsa-template", "native-server", "native-server-key", "client-trust", "server-cache", "webhook-cache", "webhook-cache-key", "webhook-public", "webhook-key", "class-key", "legacy-class-key", "inventory", "postgres-ca"}

type Request struct {
	Schema                                                                                  int
	Node, Phase, MachineID, Pin, BootID                                                     string
	ApplicationSHA256, ApplicationSourceSHA, ConfigSHA256, ControllerSHA256, ObserverSHA256 string
	SeedSHA256, OriginalSeedSHA256                                                          string
	Namespaces                                                                              map[string]string
}
type Manifest struct {
	Schema                                     int
	OriginalSeedSHA256, CertificateStateSHA256 string
	Slots                                      map[string]string
}
type Identity struct {
	MachineID, Hostname, BootID, PID1, PID1Executable, PID1Start string
	Namespaces                                                   map[string]string
}
type File struct {
	SHA256         string
	UID, GID, Mode uint32
	Bytes          int64
	Device, Inode  uint64
}
type Unit struct {
	Name, LoadState, ActiveState, SubState, UnitFileState, ConditionResult, FragmentPath, DropInPaths, Triggers, ControlGroup string
	MainPID, ControlPID                                                                                                       int
}
type Process struct {
	PID              int
	Start            uint64
	ExecutableSHA256 string
}
type Socket struct {
	Protocol, Local, Remote, State string
	Inode                          uint64
}
type Mount struct {
	Device, Source, BackingFile, Filesystem, UUID string
	Bytes, CapacityBytes                          uint64
	Options                                       []string
	Image                                         File
}
type Fence struct{ Node, ConfigSHA256, ReceiptSHA256 string }
type PreparedNode struct {
	Role, Instance, ConfigSHA256, ReleaseSHA256, SourceSHA256, Receipt, TrustSHA256, CertificateStateSHA256, PolicySHA256 string
	Ready                                                                                                                 bool
}
type SQL struct {
	Database, Deployment, Transition, ManifestSHA256              string
	Epoch                                                         time.Time
	Enabled, Blocked, WorkersAllowed                              bool
	Ready                                                         int
	Prepared                                                      []PreparedNode
	WriterFences, WorkerFences                                    []Fence
	WorkRows, AttemptRows, GuardRows                              int
	WorkSHA256, AttemptsSHA256, GuardsSHA256, AuthorizationSHA256 string
}
type Result struct {
	Schema                                                                                                                       int
	RequestSHA256, Node, Phase                                                                                                   string
	ObservedAt                                                                                                                   time.Time
	Identity                                                                                                                     Identity
	ApplicationSHA256, ApplicationSourceSHA, ConfigSHA256, ControllerSHA256, ObserverSHA256, SeedSHA256, OriginalSeedSHA256, Pin string
	Units                                                                                                                        []Unit
	Processes                                                                                                                    []Process
	Sockets                                                                                                                      []Socket
	Preserved                                                                                                                    map[string]File
	State                                                                                                                        map[string]File
	Collector                                                                                                                    Mount
	SQL                                                                                                                          SQL
	WorkerFenceSHA256                                                                                                            string
}
