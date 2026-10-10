//go:build linux

package main

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"slices"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/adoption"
	sc "github.com/CampusTech/cloud-8021x/tests/runtime/task11-acceptance/scenariocontract"
	"golang.org/x/sys/unix"
)

type scenarioPlatformPin struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}
type scenarioPlatformNode struct {
	Name         string `json:"name"`
	Machine      string `json:"machine"`
	Root         string `json:"root"`
	Namespace    string `json:"namespace"`
	Address      string `json:"address"`
	MachineID    string `json:"machine_id"`
	ConfigSHA256 string `json:"config_sha256"`
}
type scenarioPlatformAux struct {
	Name      string `json:"name"`
	Root      string `json:"root"`
	Namespace string `json:"namespace"`
	Address   string `json:"address"`
}
type scenarioPlatformInventory struct {
	Schema          int                            `json:"schema"`
	PlanSHA256      string                         `json:"plan_sha256"`
	InputSHA256     string                         `json:"input_sha256"`
	CandidateSHA256 string                         `json:"candidate_sha256"`
	Nodes           []scenarioPlatformNode         `json:"nodes"`
	Auxiliary       []scenarioPlatformAux          `json:"auxiliary"`
	Helpers         map[string]scenarioPlatformPin `json:"helpers"`
}
type scenarioPhysicalInputs struct {
	pins     sc.Pins
	caseName string
	plan     []byte
	epoch    time.Time
}

func scenarioControllerLock() (func(), error) {
	parent, err := privateParent(control+"/controller.lock", 0)
	if err != nil {
		return nil, errScenarioController
	}
	fd, err := unix.Openat(parent, "controller.lock", unix.O_RDWR|unix.O_CREAT|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0600)
	if err != nil {
		_ = unix.Close(parent)
		return nil, errScenarioController
	}
	unlock := func() { _ = unix.Close(fd); _ = unix.Close(parent) }
	if fileStat(fd, 0, 0) != nil || unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB) != nil {
		unlock()
		return nil, errScenarioController
	}
	return unlock, nil
}
func scenarioValidatePlatform(raw []byte, e enrollment, scenarioSHA string) error {
	var v scenarioPlatformInventory
	var fields map[string]json.RawMessage
	if len(raw) > 1<<20 || decodeExactJSON(raw, &v) != nil || decodeExactJSON(raw, &fields) != nil || len(fields) != 7 {
		return errScenarioController
	}
	for _, name := range []string{"schema", "plan_sha256", "input_sha256", "candidate_sha256", "nodes", "auxiliary", "helpers"} {
		if fields[name] == nil {
			return errScenarioController
		}
	}
	if v.Schema != 1 || !validSHA(v.PlanSHA256) || !validSHA(v.InputSHA256) || !validSHA(v.CandidateSHA256) || len(v.Nodes) != 4 || len(v.Auxiliary) != 3 || len(v.Helpers) != 7 {
		return errScenarioController
	}
	fixed := map[string][2]string{"blue-primary": {"c11-bp", "10.203.11.31"}, "blue-secondary": {"c11-bs", "10.203.11.32"}, "green-primary": {"c11-gp", "10.203.11.21"}, "green-secondary": {"c11-gs", "10.203.11.22"}}
	seen := map[string]bool{}
	for _, n := range v.Nodes {
		want, ok := fixed[n.Name]
		enrolled := e.Nodes[n.Name]
		if !ok || seen[n.Name] || n.Machine != "task11-"+n.Name || n.Root != "/var/lib/cloud8021x-task11/roots/task11-"+n.Name || n.Namespace != want[0] || n.Address != want[1] || n.MachineID != enrolled.MachineID || !validSHA(n.ConfigSHA256) || !validSHA(enrolled.Pin) {
			return errScenarioController
		}
		seen[n.Name] = true
	}
	aux := map[string]string{"api": "10.203.11.10", "pg": "10.203.11.11", "nas": "10.203.11.40"}
	seen = map[string]bool{}
	for _, a := range v.Auxiliary {
		ip, ok := aux[a.Name]
		if !ok || seen[a.Name] || a.Root != "/var/lib/cloud8021x-task11/aux/"+a.Name || a.Namespace != "c11-"+a.Name || a.Address != ip {
			return errScenarioController
		}
		seen[a.Name] = true
	}
	for _, name := range []string{"task11-acceptance", "task11-passive-audit", "task11-cloud-contract", "task11-assembly-seed", "task11-blue-migration", "task11-systemd-fixture", "task11-scenarios"} {
		pin, ok := v.Helpers[name]
		if !ok || pin.Path != "/usr/local/libexec/"+name || !validSHA(pin.SHA256) {
			return errScenarioController
		}
	}
	if v.Helpers["task11-acceptance"].SHA256 != e.ControllerSHA256 || v.Helpers["task11-passive-audit"].SHA256 != e.Passive.ObserverSHA256 || v.Helpers["task11-cloud-contract"].SHA256 != e.Cloud.HelperSHA256 || v.Helpers["task11-scenarios"].SHA256 != scenarioSHA {
		return errScenarioController
	}
	return nil
}
func scenarioOriginalDNS(e enrollment) error {
	files, err := originalInputs(e)
	if err != nil {
		return errScenarioController
	}
	defer clearInputs(files)
	var spec seedSpec
	if decodeExactJSON(files["spec.json"], &spec) != nil || spec.ServerDNS != "radius.task11.test" {
		return errScenarioController
	}
	leaf, _ := pem.Decode(files["source/etc/freeradius/3.0/certs/server.pem"])
	if leaf == nil || leaf.Type != "CERTIFICATE" {
		return errScenarioController
	}
	cert, err := x509.ParseCertificate(leaf.Bytes)
	if err != nil || cert.VerifyHostname(spec.ServerDNS) != nil {
		return errScenarioController
	}
	return nil
}
func scenarioPhysicalBinding(ctx context.Context, stage sc.Stage, e enrollment) (scenarioPhysicalInputs, error) {
	var out scenarioPhysicalInputs
	encoded, err := json.Marshal(stage)
	if err != nil {
		return out, errScenarioController
	}
	exact, err := sc.DecodeStage(encoded)
	if err != nil || exact.Stage != "scenario-operation" {
		return out, errScenarioController
	}
	request, err := readPrivate(fmt.Sprintf("%s/scenarios/requests/%s-%d.json", control, stage.AttemptID, stage.Sequence), sc.MaxRequestBytes, 0)
	if err != nil {
		return out, errScenarioController
	}
	defer clear(request)
	r, err := sc.DecodeRequest(request)
	if err != nil || r.AttemptID != stage.AttemptID || r.Sequence != stage.Sequence || adoption.Digest(request) != stage.RequestSHA256 {
		return out, errScenarioController
	}
	platform, err := readPrivate(control+"/platform-inventory.json", 1<<20, 0)
	if err != nil {
		return out, errScenarioController
	}
	defer clear(platform)
	enrollmentRaw, err := readPrivate(control+"/enrollment.json", 64<<10, 0)
	if err != nil {
		return out, errScenarioController
	}
	defer clear(enrollmentRaw)
	// Overlayed phase evidence is intentionally never marshaled into this pin.
	if validateScenarioPhysicalEnrollment(enrollmentRaw, e) != nil || scenarioValidatePlatform(platform, e, r.ScenarioSHA256) != nil || r.PlatformSHA256 != adoption.Digest(platform) || r.EnrollmentSHA256 != adoption.Digest(enrollmentRaw) || r.ApplicationSHA256 != e.ApplicationSHA256 || scenarioInstalledFile(control+"/public/cloud-8021x", e.ApplicationSHA256, 0755, 256<<20) != nil || scenarioOriginalDNS(e) != nil {
		return out, errScenarioController
	}
	out.caseName, out.plan, err = selectScenarioPlan(r.PlanSHA256, readPrivate)
	if err != nil {
		return out, errScenarioController
	}
	cfg, err := remoteConfig(ctx, "blue-primary", e)
	if err != nil || cfg.Deployment.CollectionEpoch.IsZero() {
		clear(out.plan)
		return scenarioPhysicalInputs{}, errScenarioController
	}
	out.epoch = cfg.Deployment.CollectionEpoch
	out.pins = sc.Pins{PlanSHA256: adoption.Digest(out.plan), PlatformSHA256: adoption.Digest(platform), EnrollmentSHA256: adoption.Digest(enrollmentRaw), ApplicationSHA256: e.ApplicationSHA256, ScenarioSHA256: r.ScenarioSHA256}
	if out.pins != r.Pins {
		clear(out.plan)
		return scenarioPhysicalInputs{}, errScenarioController
	}
	return out, nil
}
func scenarioReaderBody(ctx context.Context, e enrollment, claim *scenarioClaim, result *sc.Result) error {
	r := claim.request
	node, operation := r.Node, "scenario-accounting"
	var selection []byte
	if r.Action == "read-ca-issued" {
		var err error
		selection, _, err = claim.ReadCASelection()
		if err != nil {
			return errScenarioController
		}
		defer clear(selection)
		// The original primary holds the same preserved HA CA database credentials
		// throughout adoption/deactivation; this reads one selected actual row only.
		node, operation = "blue-primary", "scenario-ca"
	}
	input, err := json.Marshal(scenarioNodeInput{Schema: 1, RequestBytes: claim.raw, ConfigSHA256: e.Nodes[node].ConfigSHA256, Selection: selection})
	if err != nil || len(input) > maxScenarioNodeInput {
		clear(input)
		return errScenarioController
	}
	defer clear(input)
	raw, err := nodeCall(ctx, node, e, []string{operation}, input, sc.MaxResultBytes, 45*time.Second)
	if err != nil {
		clear(raw)
		return errScenarioController
	}
	defer clear(raw)
	if r.Action == "read-accounting" {
		result.Ledger = &sc.LedgerObservation{}
		err = decodeExactJSON(raw, result.Ledger)
	} else {
		result.CAIssued = &sc.CAObservation{}
		err = decodeExactJSON(raw, result.CAIssued)
	}
	if err != nil {
		return errScenarioController
	}
	return nil
}
func executeScenarioStage(ctx context.Context, stage sc.Stage) error {
	if fixtureGuard() != nil {
		return errScenarioController
	}
	if _, err := controllerGroup(ctx); err != nil {
		return errScenarioController
	}
	e, err := loadEnrollment()
	if err != nil {
		return errScenarioController
	}
	self, err := os.Open("/proc/self/exe")
	if err != nil {
		return errScenarioController
	}
	err = nasPinnedELF(self, e.ControllerSHA256, 0)
	_ = self.Close()
	if err != nil {
		return errScenarioController
	}
	unlock, err := scenarioControllerLock()
	if err != nil {
		return err
	}
	defer unlock()
	inputs, err := scenarioPhysicalBinding(ctx, stage, e)
	if err != nil {
		return err
	}
	defer clear(inputs.plan)
	store, err := openScenarioRecords()
	if err != nil {
		return errScenarioController
	}
	defer func() { _ = store.Close() }()
	claim, err := store.Admit(stage, inputs.pins)
	if err != nil {
		return errScenarioController
	}
	defer clear(claim.raw)
	defer clear(claim.RequestRaw)
	completed := false
	defer func() {
		if !completed {
			_ = claim.Fail("operation-uncertain", true)
		}
	}()
	var selection, prior []byte
	if claim.request.Authority == "rsa" && (claim.request.Action == "nas-ca-adopted" || claim.request.Action == "nas-ca-passive") {
		selection, _, err = claim.ReadCASelection()
		if err != nil {
			return errScenarioController
		}
		defer clear(selection)
		prior, err = store.read("results", fmt.Sprintf("%s-%d.json", claim.request.AttemptID, claim.request.IssuanceSequence), 32<<10)
		if err != nil {
			return errScenarioController
		}
		defer clear(prior)
	}
	private, err := scenarioPrivateInput(claim, inputs.plan, selection, prior)
	if err != nil {
		return err
	}
	defer clear(private)
	started := time.Now().UTC()
	admitted, err := nasDescriptorCall(ctx, e, inputs.pins.ScenarioSHA256, "admit", private)
	if err != nil {
		clear(admitted)
		return errScenarioController
	}
	_, err = validateScenarioAdmission(admitted, claim, inputs.caseName, e.Passive.OriginalSeedSHA256, inputs.epoch)
	clear(admitted)
	if err != nil {
		return err
	}
	result := sc.Result{Schema: 1, Kind: "scenario-operation", AttemptID: claim.request.AttemptID, Sequence: claim.request.Sequence, Action: claim.request.Action, Pins: inputs.pins, RequestSHA256: claim.sha, StartedAt: started}
	action := claim.request.Action
	switch {
	case action == "read-accounting" || action == "read-ca-issued":
		err = scenarioReaderBody(ctx, e, claim, &result)
	case slices.Contains([]string{"nas-native", "nas-ongoing", "nas-duplicates", "nas-outage", "nas-ca-original", "nas-ca-adopted", "nas-ca-passive"}, action):
		var raw []byte
		raw, err = nasDescriptorCall(ctx, e, inputs.pins.ScenarioSHA256, action, private)
		if err == nil {
			if claim.request.Authority != "" {
				result.CA = &sc.CAResult{}
				err = decodeExactJSON(raw, result.CA)
			} else {
				result.NAS = &sc.NASResult{}
				err = decodeExactJSON(raw, result.NAS)
			}
		}
		clear(raw)
	default:
		err = scenarioControlBody(ctx, e, claim, &result, scenarioControl)
	}
	if err != nil {
		return errScenarioController
	}
	after, err := scenarioPhysicalBinding(ctx, stage, e)
	if err != nil {
		return errScenarioController
	}
	defer clear(after.plan)
	if after.pins != inputs.pins || after.caseName != inputs.caseName || !after.epoch.Equal(inputs.epoch) {
		return errScenarioController
	}
	// Both namespace transports return only after actual scoped cleanup. Publication
	// rechecks protected request/history again and retains any uncertain partial file.
	result.FinishedAt = time.Now().UTC()
	result.Retired = true
	raw, err := json.Marshal(result)
	if err != nil || len(raw) > sc.MaxResultBytes {
		clear(raw)
		return errScenarioController
	}
	defer clear(raw)
	if claim.PublishResult(raw) != nil {
		return errScenarioController
	}
	completed = true
	return nil
}
