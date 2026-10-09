package main

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/adoption"
	"github.com/CampusTech/cloud-8021x/internal/config"
	audit "github.com/CampusTech/cloud-8021x/tests/runtime/task11-passive-audit/contract"
)

// These are protocol acceptance/rejection tests, not installed observation proof.
func TestPassiveResultBindsIndependentManifestRequestAndSQL(t *testing.T) {
	pin := strings.Repeat("a", 64)
	now := time.Now().UTC().Truncate(time.Second)
	r := audit.Request{Schema: 1, Node: "green-primary", Phase: "prepared", MachineID: strings.Repeat("1", 32), Pin: pin, BootID: "11111111-2222-4333-8444-555555555555", ApplicationSHA256: pin, ApplicationSourceSHA: strings.Repeat("b", 40), ConfigSHA256: pin, ControllerSHA256: pin, ObserverSHA256: pin, SeedSHA256: pin, OriginalSeedSHA256: pin, Namespaces: map[string]string{}}
	for _, name := range audit.NamespaceNames {
		r.Namespaces[name] = name + ":[123]"
	}
	m := audit.Manifest{Schema: 1, OriginalSeedSHA256: pin, CertificateStateSHA256: pin, Slots: map[string]string{}}
	out := audit.Result{Schema: 1, Node: r.Node, Phase: r.Phase, ObservedAt: now, Identity: audit.Identity{MachineID: r.MachineID, Hostname: "task11-green-primary", BootID: r.BootID, PID1: "systemd", PID1Executable: "/usr/lib/systemd/systemd", PID1Start: "123", Namespaces: r.Namespaces}, ApplicationSHA256: pin, ApplicationSourceSHA: r.ApplicationSourceSHA, ConfigSHA256: pin, ControllerSHA256: pin, ObserverSHA256: pin, SeedSHA256: pin, OriginalSeedSHA256: pin, Pin: pin, Preserved: map[string]audit.File{}, State: map[string]audit.File{}, Collector: audit.Mount{Filesystem: "ext4", UUID: "fixture-fs", BackingFile: "/var/lib/cloud-8021x/collector.img", Bytes: 512 << 20, Image: audit.File{Bytes: 512 << 20, Inode: 2}}}
	for _, slot := range audit.Slots {
		m.Slots[slot] = pin
		out.Preserved[slot] = audit.File{SHA256: pin, Bytes: 1, Inode: 1}
	}
	for _, key := range []string{audit.Executable, helper, "/usr/local/bin/cloud-8021x", "installed-config", "staged-config", "artifact-manifest", "seed-manifest", "/var/lib/cloud-8021x-bootstrap/current.json", "/var/lib/cloud-8021x-bootstrap/active-credentials.json", "/run/cloud-8021x-root/credential-set.json"} {
		out.State[key] = audit.File{SHA256: pin}
	}
	for _, name := range audit.Services {
		drop := "/etc/systemd/system/" + name + ".d/parallel.conf"
		if name == "freeradius.service" {
			drop = "/etc/systemd/system/freeradius.service.d/cloud8021x.conf " + drop
		}
		out.Units = append(out.Units, audit.Unit{Name: name, LoadState: "loaded", ActiveState: "inactive", SubState: "dead", UnitFileState: "enabled", ConditionResult: "yes", DropInPaths: drop})
	}
	for _, name := range audit.Timers {
		out.Units = append(out.Units, audit.Unit{Name: name, LoadState: "loaded", ActiveState: "inactive", SubState: "dead", UnitFileState: "enabled", FragmentPath: "/etc/systemd/system/" + name, Triggers: strings.TrimSuffix(name, ".timer") + ".service"})
	}
	c := config.Defaults()
	c.InstanceID = "radius-primary"
	c.Database.Name = "cloud8021x_task11_green"
	c.StateTransition = pin
	c.Deployment = config.Deployment{Mode: "parallel", ID: "task11-green", Instance: "task11-green-primary", SourceID: "task11-blue", SourcePrimary: "task11-blue-primary", SourceSecondary: "task11-blue-secondary", CollectionEpoch: now, SourcePrimaryKey: pin, SourceSecondaryKey: pin, DestinationPrimaryKey: pin, DestinationSecondaryKey: pin}
	b, err := adoption.ExpectedBinding(c, pin)
	if err != nil {
		t.Fatal(err)
	}
	out.SQL = audit.SQL{Database: c.Database.Name, Deployment: c.Deployment.ID, Transition: c.StateTransition, ManifestSHA256: b.ManifestSHA256, Epoch: now, WorkSHA256: pin, AttemptsSHA256: pin, GuardsSHA256: pin, AuthorizationSHA256: pin}
	for _, role := range []string{"radius-primary", "radius-secondary"} {
		out.SQL.Prepared = append(out.SQL.Prepared, audit.PreparedNode{Role: role, Instance: "task11-green" + strings.TrimPrefix(role, "radius"), ConfigSHA256: pin, ReleaseSHA256: pin, SourceSHA256: pin, Receipt: strings.Repeat("1", 32), TrustSHA256: pin, CertificateStateSHA256: pin, PolicySHA256: pin})
		out.SQL.WriterFences = append(out.SQL.WriterFences, audit.Fence{Node: role, ConfigSHA256: pin, ReceiptSHA256: pin})
	}
	request, _ := json.Marshal(r)
	out.RequestSHA256 = adoption.Digest(request)
	raw, _ := json.Marshal(out)
	if _, err = validatePassiveResult(raw, request, r, m, c, now.Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*audit.Result){
		"request": func(v *audit.Result) { v.RequestSHA256 = strings.Repeat("c", 64) },
		"boot":    func(v *audit.Result) { v.Identity.BootID = "other" },
		"source":  func(v *audit.Result) { v.ApplicationSourceSHA = strings.Repeat("c", 40) },
		"trust": func(v *audit.Result) {
			f := v.Preserved["client-trust"]
			f.SHA256 = strings.Repeat("c", 64)
			v.Preserved["client-trust"] = f
		},
		"generation":   func(v *audit.Result) { delete(v.State, "/var/lib/cloud-8021x-bootstrap/current.json") },
		"ready":        func(v *audit.Result) { v.SQL.Ready = 1; v.SQL.Prepared[0].Ready = true },
		"epoch":        func(v *audit.Result) { v.SQL.Epoch = v.SQL.Epoch.Add(time.Second) },
		"provenance":   func(v *audit.Result) { v.SQL.Prepared[1].CertificateStateSHA256 = strings.Repeat("c", 64) },
		"live-service": func(v *audit.Result) { v.Units[0].MainPID = 3 },
	} {
		t.Run(name, func(t *testing.T) {
			var changed audit.Result
			if err := json.Unmarshal(raw, &changed); err != nil {
				t.Fatal(err)
			}
			mutate(&changed)
			wire, _ := json.Marshal(changed)
			if _, err := validatePassiveResult(wire, request, r, m, c, now.Add(-time.Second)); err == nil {
				t.Fatal("mismatched observation accepted")
			}
		})
	}
	// The reverse path requires both durable worker fences and the five masks;
	// a prepared result cannot be relabeled deactivated.
	r.Phase = "deactivated"
	out.Phase = r.Phase
	out.SQL.Blocked = true
	out.SQL.WorkerFences = append([]audit.Fence(nil), out.SQL.WriterFences...)
	out.WorkerFenceSHA256 = pin
	for i := range out.Units {
		if audit.WorkerMasked(out.Units[i].Name) {
			out.Units[i].LoadState = "masked"
			out.Units[i].UnitFileState = "masked"
			out.Units[i].FragmentPath = "/dev/null"
		}
	}
	request, _ = json.Marshal(r)
	out.RequestSHA256 = adoption.Digest(request)
	deactivated, _ := json.Marshal(out)
	if _, err = validatePassiveResult(deactivated, request, r, m, c, now.Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	out.WorkerFenceSHA256 = ""
	missingFence, _ := json.Marshal(out)
	if _, err = validatePassiveResult(missingFence, request, r, m, c, now.Add(-time.Second)); err == nil {
		t.Fatal("unfenced deactivation accepted")
	}
	// Restore the prepared request for the omitted-field contract regression.
	r.Phase = "prepared"
	request, _ = json.Marshal(r)
	var omitted map[string]json.RawMessage
	_ = json.Unmarshal(raw, &omitted)
	delete(omitted, "WorkerFenceSHA256")
	missing, _ := json.Marshal(omitted)
	if _, err = validatePassiveResult(missing, request, r, m, c, now.Add(-time.Second)); err == nil {
		t.Fatal("incomplete zero-valued field accepted")
	}
}
func TestPassivePinsRequireIndependentSourceAndPhaseBindings(t *testing.T) {
	pin := strings.Repeat("a", 64)
	p := passivePins{ObserverSHA256: pin, ObserverSourceSHA256: pin, CloudSourceSHA256: pin, ApplicationSourceSHA: strings.Repeat("b", 40), OriginalSeedSHA256: pin, Manifests: map[string]string{"green-primary-prepared": pin}}
	if err := p.validate(); err != nil {
		t.Fatal(err)
	}
	p.Manifests["blue-primary-prepared"] = pin
	if p.validate() == nil {
		t.Fatal("unapproved node manifest accepted")
	}
	delete(p.Manifests, "blue-primary-prepared")
	p.ObserverSourceSHA256 = ""
	if p.validate() == nil {
		t.Fatal("unreviewed observer accepted")
	}
}
