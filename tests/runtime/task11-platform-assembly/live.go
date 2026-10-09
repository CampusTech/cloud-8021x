package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/domain"
	"golang.org/x/sys/unix"
)

func observePlatform(assembled bool) error {
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		return errors.New("actual isolated Linux root required")
	}
	marker, e := readPinned("/etc/cloud8021x-task11-fixture", digest([]byte("synthetic-only-v1\n")), 64, false)
	if e != nil || string(marker) != "synthetic-only-v1\n" {
		return errors.New("protected fixture marker absent")
	}
	st, e := os.Lstat("/etc/cloud8021x-task11-fixture")
	if e != nil || st.Mode().Perm() != 0644 {
		return errors.New("fixture marker mode differs")
	}
	comm, e := os.ReadFile("/proc/1/comm")
	if e != nil {
		return e
	}
	exe, e := os.Readlink("/proc/1/exe")
	if e != nil {
		return e
	}
	_, ce := os.Lstat("/run/systemd/container")
	_, existing := os.Lstat(platformRoot + "/images")
	f := platformFacts{Linux: true, Root: true, Marker: true, Systemd: strings.TrimSpace(string(comm)) == "systemd" && (exe == "/usr/lib/systemd/systemd" || exe == "/lib/systemd/systemd"), Container: ce == nil, Existing: existing == nil}
	links, e := os.ReadDir("/sys/class/net")
	if e != nil {
		return e
	}
	for _, v := range links {
		if _, e = os.Stat("/sys/class/net/" + v.Name() + "/device"); e == nil {
			return errors.New("physical NIC present")
		}
		f.Links = append(f.Links, v.Name())
	}
	return validatePlatform(f, assembled)
}
func measuredFree() (int64, int64, error) {
	var s unix.Statfs_t
	e := unix.Statfs(platformRoot, &s)
	if e != nil {
		return 0, 0, e
	}
	return int64(s.Bavail) * int64(s.Bsize), int64(s.Ffree), nil
}
func (o operation) preflight() error {
	if e := o.call("task11-systemd-fixture", "prerequisites", "--final"); e != nil {
		return e
	}
	b, e := o.r.call(o.ctx, "dpkg-query", "-W", "-f=${binary:Package}\t${Version}\t${Architecture}\t${db:Status-Abbrev}\n")
	if e != nil || digest(b) != o.in.Plan.BaselineSHA256 || len(strings.Split(strings.TrimSpace(string(b)), "\n")) != 347 {
		return errors.New("actual independently pinned347 package inventory differs")
	}
	b, e = o.r.call(o.ctx, "dpkg", "--audit")
	if e != nil || strings.TrimSpace(string(b)) != "" {
		return errors.New("actual base audit is not empty")
	}
	free, inodes, e := measuredFree()
	if e != nil {
		return e
	}
	if free < o.in.Plan.Budget.FreeBytes || inodes < o.in.Plan.Budget.FreeInodes {
		return errors.New("actual capacity below independently measured admission")
	}
	// All executable paths are verified before any operation can indirectly use them.
	for _, p := range o.in.Plan.Tools {
		f, e := openPinned(p.Path, p.SHA256, 160<<20, false)
		if e != nil {
			return e
		}
		_ = f.Close()
	}
	for _, p := range []pin{{controlRoot + "/blue-migration.json", o.in.Plan.BluePlanSHA256}, {publicRoot + "/task11-acceptance.service", o.in.Plan.ControllerUnitSHA256}} {
		f, e := openPinned(p.Path, p.SHA256, 1<<20, false)
		if e != nil {
			return e
		}
		_ = f.Close()
	}
	for _, root := range []string{originalRoot + "/api", controlRoot + "/primitive-api"} {
		for _, f := range []string{"remote-state.json", "journal.jsonl", "state.lock", "incomplete.json", "driver-attempt.lock", "verified-result.json"} {
			if _, e = os.Lstat(root + "/" + f); !os.IsNotExist(e) {
				return errors.New("remote root already used or uncertain")
			}
		}
	}
	return nil
}
func (o operation) initializePostgres() error {
	if e := o.pg("initdb", "-D", "/var/lib/postgresql/17/main", "--auth-local=peer", "--auth-host=scram-sha-256", "--no-instructions"); e != nil {
		return e
	}
	if e := o.call("systemctl", "start", "task11-postgres.service"); e != nil {
		return e
	}
	deadline := time.NewTimer(15 * time.Second)
	defer deadline.Stop()
	for o.pg("pg_isready", "--host=/var/lib/postgresql/run", "--username=postgres", "--dbname=postgres", "--timeout=1") != nil {
		select {
		case <-o.ctx.Done():
			return errors.New("PostgreSQL readiness deadline exceeded")
		case <-deadline.C:
			return errors.New("PostgreSQL readiness deadline exceeded")
		case <-time.After(200 * time.Millisecond):
		}
	}
	// Socket is deliberately private to the PG root; no administrator credential leaves it.
	return o.pg("psql", "--host=/var/lib/postgresql/run", "--username=postgres", "--dbname=postgres", "--set=ON_ERROR_STOP=1", "--file=/etc/task11-postgres/init.sql")
}
func (o operation) migrateBlue() error {
	return o.call("systemd-run", "--quiet", "--wait", "--pipe", "--machine=task11-blue-primary", "--service-type=exec", "--property=RuntimeMaxSec=240", "/usr/local/libexec/task11-blue-migration", "--plan-sha256", o.in.Plan.BluePlanSHA256)
}
func (o operation) startBlue() error {
	for _, n := range o.in.Plan.Nodes {
		if strings.HasPrefix(n.Name, "blue-") {
			if e := o.call("systemctl", "--machine=task11-"+n.Name, "start", "systemd-tmpfiles-setup.service"); e != nil {
				return e
			}
			if e := o.call("systemctl", "--machine=task11-"+n.Name, "enable", "--now", "task11-source-policy.service", "acme-authz-webhook.service", "step-ca.service", "step-ca-rsa.service", "freeradius.service", "radius-source-refresh.timer"); e != nil {
				return e
			}
		}
	}
	return nil
}

type primitiveResult struct {
	Schema             int    `json:"schema"`
	Gate               string `json:"gate"`
	ApplicationSHA256  string `json:"application_sha256"`
	Phase              string `json:"phase"`
	SecretPublication  bool   `json:"secret_publication"`
	SecretPreservation bool   `json:"secret_preservation"`
	FleetUncertainty   bool   `json:"fleet_uncertainty"`
	OTLPDecoding       bool   `json:"otlp_decoding"`
	OrdinaryTelemetry  bool   `json:"ordinary_telemetry"`
	EvidenceSHA256     string `json:"evidence_sha256"`
	Records            int    `json:"records"`
	Metrics            int    `json:"metrics"`
}

func validatePrimitiveResult(raw []byte, application string) error {
	var v primitiveResult
	if domain.DecodeJSONStrict(raw, &v) != nil || v.Schema != 1 || v.Gate != "primitive-contract" || v.Phase != "primitive-only" || v.ApplicationSHA256 != application || !v.SecretPublication || !v.SecretPreservation || !v.FleetUncertainty || !v.OTLPDecoding || v.Records < 1 || v.Metrics < 1 || len(v.EvidenceSHA256) != 64 {
		return errors.New("genuine complete primitive-only result required")
	}
	return nil
}
func (o operation) verifyPrimitive(resultPin string) error {
	raw, e := readPinned(controlRoot+"/primitive-api/verified-result.json", resultPin, 4096, true)
	if e != nil {
		return e
	}
	if e = validatePrimitiveResult(raw, o.in.Plan.ApplicationSHA256); e != nil {
		return e
	}
	actual, e := o.r.call(o.ctx, "task11-cloud-contract", "verify", "--gate", "primitive-contract", "--application-sha256", o.in.Plan.ApplicationSHA256, "--expected-sha256", o.in.Plan.PrimitiveExpectedSHA256)
	if e != nil {
		return e
	}
	if e = validatePrimitiveResult(actual, o.in.Plan.ApplicationSHA256); e != nil {
		return e
	}
	var a, b primitiveResult
	_ = json.Unmarshal(raw, &a)
	_ = json.Unmarshal(actual, &b)
	if a != b {
		return errors.New("current actual primitive journal differs from independently pinned result")
	}
	return nil
}
func (o operation) step(name, resultPin string) error {
	switch name {
	case "preflight":
		return o.preflight()
	case "lower":
		return o.lower()
	case "private-roots":
		return o.privateRoots()
	case "network":
		return o.network()
	case "units":
		if e := o.auditLoops(); e != nil {
			return e
		}
		return o.units()
	case "inventory":
		return o.inventory()
	case "start-primitive":
		return o.call("systemctl", "start", "task11-api-primitive.service")
	case "verify-primitive":
		return o.verifyPrimitive(resultPin)
	case "stop-primitive":
		if e := o.call("systemctl", "stop", "task11-api-primitive.service"); e != nil {
			return e
		}
		b, e := o.r.call(o.ctx, "systemctl", "show", "task11-api-primitive.service", "--property=ActiveState", "--property=MainPID")
		if e != nil || !strings.Contains(string(b), "ActiveState=inactive\n") || !strings.Contains(string(b), "MainPID=0\n") {
			return errors.New("primitive API stop uncertain")
		}
		return nil
	case "start-installed-api":
		return o.call("systemctl", "start", "task11-api-installed.service")
	case "initialize-postgres":
		return o.initializePostgres()
	case "start-nodes":
		for _, n := range o.in.Plan.Nodes {
			if e := o.call("systemctl", "start", "task11-node-"+n.Name+".service"); e != nil {
				return e
			}
		}
		return nil
	case "migrate-blue":
		return o.migrateBlue()
	case "start-blue-services":
		return o.startBlue()
	default:
		return fmt.Errorf("unknown operation %q", name)
	}
}
func (o operation) run(stage, sha, resultPin string) error {
	fd, e := parent(controlRoot+"/platform-operation.lock", false)
	if e != nil {
		return e
	}
	defer func() { _ = unix.Close(fd) }()
	lock, e := unix.Openat(fd, "platform-operation.lock", unix.O_CREAT|unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0600)
	if e != nil {
		return e
	}
	defer func() { _ = unix.Close(lock) }()
	var st unix.Stat_t
	if unix.Fstat(lock, &st) != nil || st.Uid != 0 || st.Nlink != 1 || st.Mode&0777 != 0600 {
		return errors.New("unsafe operation lock")
	}
	if e = unix.Flock(lock, unix.LOCK_EX|unix.LOCK_NB); e != nil {
		return errors.New("another platform operation holds lock")
	}
	if e = beginAttempt(controlRoot+"/platform-"+stage+".attempt", stage, sha); e != nil {
		return e
	}
	steps, e := stageOrder(stage)
	if e != nil {
		return e
	}
	for _, step := range steps {
		if e = o.step(step, resultPin); e != nil {
			return e
		}
	}
	return nil
}

func (o operation) capacityAfterAssembly() error {
	free, inodes, e := measuredFree()
	if e != nil {
		return e
	}
	if free < GiB || inodes < 100000 {
		return errors.New("actual final outer free reserve violated")
	}
	f, e := openPinned(publicRoot+"/cloud-8021x", o.in.Plan.ApplicationSHA256, 160<<20, false)
	if e != nil {
		return e
	}
	st, e := f.Stat()
	_ = f.Close()
	if e != nil {
		return e
	}
	// Reserve the actual app copy and independently measured future private/native
	// writes in addition to the unmodified product collector's full512MiB image.

	for _, name := range []string{"green-primary", "green-secondary"} {
		var fs unix.Statfs_t
		if unix.Statfs(rootFor(name), &fs) != nil {
			return errors.New("actual green filesystem unavailable")
		}
		if e = validateGreenAvailable(int64(fs.Bavail)*int64(fs.Bsize), st.Size(), o.in.Plan.Budget.PrivateBytes, uint64(fs.Ffree)); e != nil {
			return e
		}
	}
	return nil
}
