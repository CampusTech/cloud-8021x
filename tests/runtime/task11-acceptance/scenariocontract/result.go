package scenariocontract

import (
	"time"

	"github.com/CampusTech/cloud-8021x/internal/accounting"
	"github.com/CampusTech/cloud-8021x/internal/accounting/binding"
)

// Result contains measured observations, not a product readiness assertion.
// Retired may be published only after the controller's actual process cleanup.
type Result struct {
	Schema    int    `json:"schema"`
	Kind      string `json:"kind"`
	AttemptID string `json:"attempt_id"`
	Sequence  int    `json:"sequence"`
	Action    string `json:"action"`
	Pins
	RequestSHA256 string                `json:"request_sha256"`
	StartedAt     time.Time             `json:"started_at"`
	FinishedAt    time.Time             `json:"finished_at"`
	Retired       bool                  `json:"retired"`
	Probe         *PairObservation      `json:"probe,omitempty"`
	Ledger        *LedgerObservation    `json:"ledger,omitempty"`
	Lifecycle     *LifecycleObservation `json:"lifecycle,omitempty"`
	NAS           *NASResult            `json:"nas,omitempty"`
	CA            *CAResult             `json:"ca,omitempty"`
	CAIssued      *CAObservation        `json:"ca_issued,omitempty"`
	Gate          *GateObservation      `json:"gate,omitempty"`
	Cleanup       *CleanupObservation   `json:"cleanup,omitempty"`
}

type UnitObservation struct {
	Name             string   `json:"name"`
	ActiveState      string   `json:"active_state"`
	SubState         string   `json:"sub_state"`
	MainPID          int      `json:"main_pid"`
	ExecutableSHA256 string   `json:"executable_sha256"`
	ControlGroup     string   `json:"control_group"`
	ProcessCgroup    string   `json:"process_cgroup"`
	FragmentPath     string   `json:"fragment_path"`
	DropInPaths      []string `json:"drop_in_paths"`
}
type CollectorObservation struct {
	BackingFile string   `json:"backing_file"`
	FileDevice  uint64   `json:"file_device"`
	FileInode   uint64   `json:"file_inode"`
	ByteSize    uint64   `json:"byte_size"`
	Filesystem  string   `json:"filesystem"`
	MountDevice string   `json:"mount_device"`
	Options     []string `json:"options"`
	MountActive bool     `json:"mount_active"`
}
type NodeObservation struct {
	Machine           string                     `json:"machine"`
	Root              string                     `json:"root"`
	MachineID         string                     `json:"machine_id"`
	BootID            string                     `json:"boot_id"`
	Leader            int                        `json:"leader"`
	LeaderStartTicks  uint64                     `json:"leader_start_ticks"`
	Namespaces        map[string]uint64          `json:"namespaces"`
	ApplicationSHA256 string                     `json:"application_sha256"`
	ConfigSHA256      string                     `json:"config_sha256"`
	Deployment        string                     `json:"deployment"`
	Epoch             time.Time                  `json:"epoch"`
	WorkersActive     bool                       `json:"workers_active"`
	WorkersBlocked    bool                       `json:"workers_blocked"`
	ReadyRoles        int                        `json:"ready_roles"`
	Units             map[string]UnitObservation `json:"units"`
	Collector         CollectorObservation       `json:"collector"`
}
type PairObservation struct {
	Nodes map[string]NodeObservation `json:"nodes"`
}

type SessionObservation struct {
	SessionKey             string           `json:"session_key"`
	State                  accounting.State `json:"state"`
	NativeBaselineRequired bool             `json:"native_baseline_required"`
	Pending                bool             `json:"pending"`
}
type EventObservation struct {
	EventID    string           `json:"event_id"`
	IntakeID   int64            `json:"intake_id"`
	SessionKey string           `json:"session_key"`
	ReceivedAt time.Time        `json:"received_at"`
	Event      accounting.Event `json:"event"`
	Reason     string           `json:"reason"`
}
type IntervalObservation struct {
	UsageID    string              `json:"usage_id"`
	EventID    string              `json:"event_id"`
	SessionKey string              `json:"session_key"`
	Interval   accounting.Interval `json:"interval"`
}

// Opaque fields preserve the exact stored PostgreSQL bytes through base64 JSON.
// Never substitute a json.RawMessage or reconstructed business record.
type AttemptObservation struct {
	Generation int64      `json:"generation"`
	Owner      string     `json:"owner"`
	StartedAt  time.Time  `json:"started_at"`
	FinishedAt *time.Time `json:"finished_at,omitempty"`
	Outcome    *string    `json:"outcome,omitempty"`
	Receipt    []byte     `json:"receipt,omitempty"`
}
type WorkObservation struct {
	ID               string               `json:"id"`
	Kind             string               `json:"kind"`
	Payload          []byte               `json:"payload"`
	CreatedAt        time.Time            `json:"created_at"`
	State            string               `json:"state"`
	Receipt          []byte               `json:"receipt,omitempty"`
	Attempts         []AttemptObservation `json:"attempts"`
	RecoveryEvidence []byte               `json:"recovery_evidence,omitempty"`
}
type LedgerObservation struct {
	Deployment   string                `json:"deployment"`
	Database     string                `json:"database"`
	Epoch        time.Time             `json:"epoch"`
	ConfigSHA256 string                `json:"config_sha256"`
	ReadOnly     bool                  `json:"read_only"`
	Isolation    string                `json:"isolation"`
	Sessions     []SessionObservation  `json:"sessions"`
	Observations []EventObservation    `json:"observations"`
	Intervals    []IntervalObservation `json:"intervals"`
	Outbox       []WorkObservation     `json:"outbox"`
}

type LifecycleObservation struct {
	Unit             string           `json:"unit"`
	Before           *NodeObservation `json:"before,omitempty"`
	After            *NodeObservation `json:"after,omitempty"`
	OldLeaderRetired bool             `json:"old_leader_retired"`
	UnitActiveState  string           `json:"unit_active_state"`
	UnitSubState     string           `json:"unit_sub_state"`
}
type NASExpected struct {
	EventIDs      []string `json:"event_ids"`
	UsageIDs      []string `json:"usage_ids"`
	UploadBytes   uint64   `json:"upload_bytes"`
	DownloadBytes uint64   `json:"download_bytes"`
	Seconds       uint64   `json:"seconds"`
}
type EAPResult struct {
	Accepted                    bool   `json:"accepted"`
	Rejected                    bool   `json:"rejected"`
	ResponseCode                int    `json:"response_code"`
	ResponseAuthenticatorSHA256 string `json:"response_authenticator_sha256"`
	TunnelType                  int    `json:"tunnel_type"`
	TunnelMediumType            int    `json:"tunnel_medium_type"`
	VLAN                        int    `json:"vlan"`
}
type AccountingPacketResult struct {
	Peer                        string    `json:"peer"`
	PacketID                    uint8     `json:"packet_id"`
	Status                      int       `json:"status"`
	Duration                    uint32    `json:"duration"`
	UploadBytes                 uint64    `json:"upload_bytes"`
	DownloadBytes               uint64    `json:"download_bytes"`
	RequestAuthenticator        string    `json:"request_authenticator"`
	ResponseCode                int       `json:"response_code"`
	ResponseAuthenticatorSHA256 string    `json:"response_authenticator_sha256,omitempty"`
	ACK                         bool      `json:"ack"`
	SentAt                      time.Time `json:"sent_at"`
	CompletedAt                 time.Time `json:"completed_at"`
}
type NASResult struct {
	Peer        string                   `json:"peer"`
	Session     string                   `json:"session"`
	Station     string                   `json:"station"`
	ChosenAt    time.Time                `json:"chosen_at"`
	ClassSHA256 string                   `json:"class_sha256"`
	Attribution binding.Attribution      `json:"attribution"`
	Expected    NASExpected              `json:"expected"`
	EAP         EAPResult                `json:"eap"`
	Packets     []AccountingPacketResult `json:"packets"`
}
type IssuedCertificate struct {
	Serial          string    `json:"serial"`
	LeafDER         []byte    `json:"leaf_der"`
	LeafDERSHA256   string    `json:"leaf_der_sha256"`
	PublicKeySHA256 string    `json:"public_key_sha256"`
	NotBefore       time.Time `json:"not_before"`
	NotAfter        time.Time `json:"not_after"`
	Subject         string    `json:"subject"`
	ClientAuthOnly  bool      `json:"client_auth_only"`
}
type CAResponse struct {
	HTTPStatus        int    `json:"http_status"`
	Code              string `json:"code,omitempty"`
	SignatureVerified bool   `json:"signature_verified"`
	TransactionBound  bool   `json:"transaction_bound"`
	ChainVerified     bool   `json:"chain_verified"`
}
type CAResult struct {
	Authority                  string             `json:"authority"`
	Route                      string             `json:"route"`
	Phase                      string             `json:"phase"`
	Peer                       string             `json:"peer"`
	RequestSHA256              string             `json:"request_sha256"`
	SignerPublicSHA256         string             `json:"signer_public_sha256"`
	OriginalRootSHA256         string             `json:"original_root_sha256"`
	OriginalIntermediateSHA256 string             `json:"original_intermediate_sha256"`
	OriginalDecrypterSHA256    string             `json:"original_decrypter_sha256,omitempty"`
	Issued                     *IssuedCertificate `json:"issued,omitempty"`
	Response                   CAResponse         `json:"response"`
}
type CASelection struct {
	Schema                     int    `json:"schema"`
	AttemptID                  string `json:"attempt_id"`
	IssuanceSequence           int    `json:"issuance_sequence"`
	ResultSHA256               string `json:"result_sha256"`
	Authority                  string `json:"authority"`
	Serial                     string `json:"serial"`
	LeafDERSHA256              string `json:"leaf_der_sha256"`
	OriginalRootSHA256         string `json:"original_root_sha256"`
	OriginalIntermediateSHA256 string `json:"original_intermediate_sha256"`
}
type CAObservation struct {
	Authority              string `json:"authority"`
	Database               string `json:"database"`
	ReadOnly               bool   `json:"read_only"`
	Isolation              string `json:"isolation"`
	Serial                 string `json:"serial"`
	SelectionSHA256        string `json:"selection_sha256"`
	IssuanceResultSHA256   string `json:"issuance_result_sha256"`
	LeafDERSHA256          string `json:"leaf_der_sha256"`
	CertificateKey         []byte `json:"certificate_key"`
	CertificateDER         []byte `json:"certificate_der"`
	CertificateDataPresent bool   `json:"certificate_data_present"`
	CertificateDataKey     []byte `json:"certificate_data_key,omitempty"`
	CertificateData        []byte `json:"certificate_data,omitempty"`
}
type GateObservation struct {
	Unit          string    `json:"unit,omitempty"`
	MainPID       int       `json:"main_pid,omitempty"`
	OldPIDRetired bool      `json:"old_pid_retired"`
	State         string    `json:"state"`
	ObservedAt    time.Time `json:"observed_at"`
}
type ProcessObservation struct {
	HostPID      int    `json:"host_pid"`
	StartTicks   uint64 `json:"start_ticks"`
	ControlGroup string `json:"control_group"`
	Retired      bool   `json:"retired"`
}
type CleanupCase struct {
	Kind                  string               `json:"kind"`
	Processes             []ProcessObservation `json:"processes"`
	Populated             bool                 `json:"populated"`
	SentinelObservedAlive bool                 `json:"sentinel_observed_alive"`
	SentinelRetired       bool                 `json:"sentinel_retired"`
}
type CleanupObservation struct {
	Cases []CleanupCase `json:"cases"`
}
