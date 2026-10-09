package scenariocontract

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/big"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/accounting/binding"
)

func publicLeaf(t *testing.T) []byte {
	t.Helper()
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	at := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	spec := &x509.Certificate{SerialNumber: big.NewInt(1234), Subject: pkix.Name{CommonName: "synthetic-client"}, NotBefore: at.Add(-time.Hour), NotAfter: at.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	der, e := x509.CreateCertificate(rand.Reader, spec, spec, &key.PublicKey, key)
	if e != nil {
		t.Fatal(e)
	}
	return der
}
func TestGenuineCARowIdentityAndHonestECMetadataAbsence(t *testing.T) {
	r := validRequest("read-ca-issued")
	r.Sequence = 2
	r.IssuanceSequence = 1
	r.SelectionSHA256 = strings.Repeat("f", 64)
	der := publicLeaf(t)
	v := resultFor(r)
	v.CAIssued = &CAObservation{Authority: "ec", Database: "stepca", ReadOnly: true, Isolation: "repeatable-read", Serial: "1234", SelectionSHA256: r.SelectionSHA256, IssuanceResultSHA256: strings.Repeat("e", 64), LeafDERSHA256: digest(der), CertificateKey: []byte("1234"), CertificateDER: der}
	raw, _ := json.Marshal(v)
	if _, e := DecodeResult(raw, r, v.RequestSHA256); e != nil {
		t.Fatal(e)
	}
	for _, mutate := range []func(*CAObservation){func(c *CAObservation) { c.Serial = "1235" }, func(c *CAObservation) { c.CertificateKey = []byte("01234") }, func(c *CAObservation) { c.CertificateDER = []byte("not a certificate") }, func(c *CAObservation) { c.CertificateDataPresent = true }, func(c *CAObservation) { c.CertificateData = []byte(`{"provisioner":"fabricated"}`) }, func(c *CAObservation) { c.Authority = "rsa"; c.Database = "stepca_rsa" }} {
		copy := *v.CAIssued
		mutate(&copy)
		bad := v
		bad.CAIssued = &copy
		raw, _ := json.Marshal(bad)
		if _, e := DecodeResult(raw, r, v.RequestSHA256); e == nil {
			t.Fatal("substituted row or dishonest metadata absence accepted")
		}
	}
	v.CAIssued.Authority = "rsa"
	v.CAIssued.Database = "stepca_rsa"
	v.CAIssued.CertificateDataPresent = true
	v.CAIssued.CertificateDataKey = []byte("1234")
	v.CAIssued.CertificateData = []byte(` { "provisioner" : {"name":"wifi-scep"} } `)
	raw, _ = json.Marshal(v)
	got, e := DecodeResult(raw, r, v.RequestSHA256)
	if e != nil || string(got.CAIssued.CertificateData) != string(v.CAIssued.CertificateData) {
		t.Fatalf("actual RSA provisioner bytes not retained: %v", e)
	}
}
func validNAS() NASResult {
	at := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	pin := strings.Repeat("e", 64)
	vlan := 120
	return NASResult{Peer: "10.203.11.21", Session: "task11-native", Station: "02:00:00:00:00:40", ChosenAt: at, ClassSHA256: pin, Attribution: binding.Attribution{DeviceID: "fleet:1", Fingerprint: pin, VLAN: &vlan, IssuedAt: at}, Expected: NASExpected{EventIDs: []string{pin}, UploadBytes: 1 << 32}, EAP: EAPResult{Accepted: true, ResponseCode: 2, ResponseAuthenticatorSHA256: pin, TunnelType: 13, TunnelMediumType: 6, VLAN: 120}, Packets: []AccountingPacketResult{{Peer: "10.203.11.21", Status: 3, UploadBytes: 1 << 32, RequestAuthenticator: strings.Repeat("a", 32), ResponseCode: 5, ResponseAuthenticatorSHA256: pin, ACK: true, SentAt: at.Add(time.Second), CompletedAt: at.Add(2 * time.Second)}}}
}
func TestNativeObservationKeepsAuthenticatedACKSeparateFromDelivery(t *testing.T) {
	r := validRequest("nas-native")
	v := resultFor(r)
	n := validNAS()
	v.NAS = &n
	raw, _ := json.Marshal(v)
	got, e := DecodeResult(raw, r, v.RequestSHA256)
	if e != nil || !got.NAS.Packets[0].ACK {
		t.Fatalf("native packet observation refused: %v", e)
	}
	for _, mutate := range []func(*NASResult){func(n *NASResult) { n.EAP.TunnelType = 12 }, func(n *NASResult) { n.EAP.TunnelMediumType = 5 }, func(n *NASResult) { n.EAP.VLAN = 121 }, func(n *NASResult) { n.Packets[0].ResponseAuthenticatorSHA256 = "" }, func(n *NASResult) { n.Packets[0].ACK = false }, func(n *NASResult) { n.Expected.EventIDs = []string{strings.Repeat("e", 64), strings.Repeat("e", 64)} }, func(n *NASResult) { n.Station = "not a MAC" }} {
		bad := resultFor(r)
		copy := validNAS()
		mutate(&copy)
		bad.NAS = &copy
		raw, _ := json.Marshal(bad)
		if _, e := DecodeResult(raw, r, v.RequestSHA256); e == nil {
			t.Fatal("ambiguous native authentication evidence accepted")
		}
	}
}

func validNode(name string, ordinal uint64) NodeObservation {
	at := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	pin := strings.Repeat("a", 64)
	p := NodeObservation{Machine: "task11-" + name, Root: "/var/lib/cloud8021x-task11/roots/task11-" + name, MachineID: strings.Repeat("b", 31) + strconv.FormatUint(ordinal, 10), BootID: "00000000-0000-0000-0000-00000000000" + strconv.FormatUint(ordinal, 10), Leader: int(100 + ordinal), LeaderStartTicks: ordinal, Namespaces: map[string]uint64{"pid": ordinal, "mnt": ordinal + 10, "uts": ordinal + 20, "net": ordinal + 30, "cgroup": ordinal + 40}, ApplicationSHA256: pin, ConfigSHA256: pin, Deployment: "task11-green", Epoch: at, WorkersActive: true, ReadyRoles: 2, Units: map[string]UnitObservation{}, Collector: CollectorObservation{BackingFile: "/var/lib/cloud-8021x-bootstrap/collector.ext4", FileDevice: ordinal, FileInode: 2, ByteSize: 512 << 20, Filesystem: "ext4", MountDevice: "/dev/loop" + strconv.FormatUint(ordinal, 10), Options: []string{"rw", "nodev", "nosuid", "noexec"}, MountActive: true}}
	for _, name := range []string{"cloud-8021x.service", "freeradius.service", "step-ca.service", "step-ca-rsa.service", "datadog-agent.service", "datadog-agent-ddot.service"} {
		p.Units[name] = UnitObservation{Name: name, ActiveState: "active", SubState: "running", MainPID: 400, ExecutableSHA256: pin, ControlGroup: "/system.slice/" + name, ProcessCgroup: "/system.slice/" + name, FragmentPath: "/etc/systemd/system/" + name}
	}
	return p
}
func TestBothPhysicalActiveNodesRequireDistinctMeasuredNamespaces(t *testing.T) {
	r := validRequest("probe-active-pair")
	v := resultFor(r)
	v.Probe = &PairObservation{Nodes: map[string]NodeObservation{"green-primary": validNode("green-primary", 1), "green-secondary": validNode("green-secondary", 2)}}
	raw, _ := json.Marshal(v)
	if _, e := DecodeResult(raw, r, v.RequestSHA256); e != nil {
		t.Fatal(e)
	}
	for _, mutate := range []func(*NodeObservation){func(p *NodeObservation) { p.Namespaces["pid"] = 1 }, func(p *NodeObservation) { p.MachineID = strings.Repeat("b", 31) + "1" }, func(p *NodeObservation) { p.Collector.FileDevice = 1 }} {
		copy := validNode("green-secondary", 2)
		mutate(&copy)
		bad := resultFor(r)
		bad.Probe = &PairObservation{Nodes: map[string]NodeObservation{"green-primary": validNode("green-primary", 1), "green-secondary": copy}}
		raw, _ := json.Marshal(bad)
		if _, e := DecodeResult(raw, r, v.RequestSHA256); e == nil {
			t.Fatal("shared physical node, namespace or collector accepted")
		}
	}
}
func TestLifecycleAndCleanupCannotClaimRetirementFromExitCode(t *testing.T) {
	r := validRequest("reboot-green-primary")
	r.Node = "green-primary"
	v := resultFor(r)
	before := validNode("green-primary", 1)
	after := before
	after.BootID = "00000000-0000-0000-0000-000000000003"
	after.Leader = 103
	after.LeaderStartTicks = 3
	v.Lifecycle = &LifecycleObservation{Unit: "task11-node-green-primary.service", Before: &before, After: &after, OldLeaderRetired: true, UnitActiveState: "active", UnitSubState: "running"}
	raw, _ := json.Marshal(v)
	if _, e := DecodeResult(raw, r, v.RequestSHA256); e != nil {
		t.Fatal(e)
	}
	v.Lifecycle.OldLeaderRetired = false
	raw, _ = json.Marshal(v)
	if _, e := DecodeResult(raw, r, v.RequestSHA256); e == nil {
		t.Fatal("unretired old leader accepted")
	}
	r = validRequest("probe-owned-cleanup")
	v = resultFor(r)
	v.Cleanup = &CleanupObservation{}
	for _, kind := range []string{"deadline", "helper-death"} {
		v.Cleanup.Cases = append(v.Cleanup.Cases, CleanupCase{Kind: kind, SentinelObservedAlive: true, SentinelRetired: true, Processes: []ProcessObservation{{HostPID: 100, StartTicks: 10, ControlGroup: "/system.slice/task11-acceptance.service/operation-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Retired: true}, {HostPID: 101, StartTicks: 11, ControlGroup: "/system.slice/task11-acceptance.service/operation-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Retired: true}}})
	}
	raw, _ = json.Marshal(v)
	if _, e := DecodeResult(raw, r, v.RequestSHA256); e != nil {
		t.Fatal(e)
	}
	v.Cleanup.Cases[0].SentinelObservedAlive = false
	raw, _ = json.Marshal(v)
	if _, e := DecodeResult(raw, r, v.RequestSHA256); e == nil {
		t.Fatal("unrelated sentinel disappearance accepted")
	}
}
