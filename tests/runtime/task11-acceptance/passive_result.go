package main

import (
	"encoding/json"
	"errors"
	"reflect"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/adoption"
	"github.com/CampusTech/cloud-8021x/internal/config"
	audit "github.com/CampusTech/cloud-8021x/tests/runtime/task11-passive-audit/contract"
)

func validatePassiveResult(raw, request []byte, r audit.Request, m audit.Manifest, c config.Config, started time.Time) (audit.Result, error) {
	var out audit.Result
	if len(raw) > audit.MaxResultBytes || decodeExactJSON(raw, &out) != nil || audit.ValidateRequest(r) != nil || audit.ValidateManifest(m, r) != nil {
		return out, errors.New("invalid exact passive observer result")
	}
	var fields map[string]json.RawMessage
	if decodeExactJSON(raw, &fields) != nil || len(fields) != reflect.TypeFor[audit.Result]().NumField() {
		return out, errors.New("incomplete passive observer result")
	}
	if out.Schema != 1 || out.RequestSHA256 != adoption.Digest(request) || out.Node != r.Node || out.Phase != r.Phase || out.Pin != r.Pin || out.ApplicationSHA256 != r.ApplicationSHA256 || out.ApplicationSourceSHA != r.ApplicationSourceSHA || out.ConfigSHA256 != r.ConfigSHA256 || out.ControllerSHA256 != r.ControllerSHA256 || out.ObserverSHA256 != r.ObserverSHA256 || out.SeedSHA256 != r.SeedSHA256 || out.OriginalSeedSHA256 != r.OriginalSeedSHA256 || out.ObservedAt.Before(started) || out.ObservedAt.After(time.Now().UTC().Add(time.Second)) {
		return out, errors.New("passive observer request/source binding differs")
	}
	if out.Identity.MachineID != r.MachineID || out.Identity.Hostname != "task11-"+r.Node || out.Identity.BootID != r.BootID || out.Identity.PID1 != "systemd" || out.Identity.PID1Start == "" || out.Identity.PID1Executable == "" || !reflect.DeepEqual(out.Identity.Namespaces, r.Namespaces) {
		return out, errors.New("actual passive observer boot/namespace identity differs")
	}
	if audit.ValidateUnits(out.Units, r.Phase) != nil || audit.ValidateSQL(out.SQL, r.Phase) != nil {
		return out, errors.New("actual passive units/SQL rejected")
	}
	binding, err := adoption.ExpectedBinding(c, r.ApplicationSHA256)
	if err != nil || out.SQL.ManifestSHA256 != binding.ManifestSHA256 || out.SQL.Transition != c.StateTransition || !out.SQL.Epoch.Equal(c.Deployment.CollectionEpoch) {
		return out, errors.New("actual passive SQL deployment binding differs")
	}
	if len(out.Preserved) != len(audit.Slots) {
		return out, errors.New("preserved slot set differs")
	}
	for _, slot := range audit.Slots {
		f, ok := out.Preserved[slot]
		if !ok || f.SHA256 != m.Slots[slot] || f.Bytes < 1 || f.Inode == 0 {
			return out, errors.New("independent preserved slot differs")
		}
	}
	for _, key := range []string{audit.Executable, helper, "/usr/local/bin/cloud-8021x", "installed-config", "staged-config", "artifact-manifest", "seed-manifest", "/var/lib/cloud-8021x-bootstrap/current.json", "/var/lib/cloud-8021x-bootstrap/active-credentials.json", "/run/cloud-8021x-root/credential-set.json"} {
		if !validSHA(out.State[key].SHA256) {
			return out, errors.New("completed generation/credential evidence missing")
		}
	}
	for _, n := range out.SQL.Prepared {
		if n.ReleaseSHA256 != r.ApplicationSHA256 || n.TrustSHA256 != m.Slots["client-trust"] || n.CertificateStateSHA256 != m.CertificateStateSHA256 {
			return out, errors.New("actual prepared provenance differs")
		}
	}
	if r.Phase == "prepared" && out.WorkerFenceSHA256 != "" || r.Phase == "deactivated" && !validSHA(out.WorkerFenceSHA256) {
		return out, errors.New("physical worker fence differs")
	}
	if out.Collector.UUID == "" || out.Collector.BackingFile == "" || out.Collector.Filesystem != "ext4" || out.Collector.Bytes != 512<<20 || out.Collector.Image.Bytes != 512<<20 || out.Collector.Image.Inode == 0 {
		return out, errors.New("actual persistent collector storage missing")
	}
	return out, nil
}
