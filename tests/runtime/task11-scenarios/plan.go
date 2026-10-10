package main

import (
	"errors"
	"reflect"
	"regexp"
	"strings"
)

var shaPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
var machineIDPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)
var bootPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
var sessionPattern = regexp.MustCompile(`^task11-[a-z0-9-]{1,57}$`)
var fixtureDNSPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{0,80}\.task11\.test$`)

func validatePlan(p scenarioPlan) error {
	_, offset := p.CollectionEpoch.Zone()
	if p.CollectionEpoch.IsZero() || p.CollectionEpoch.Nanosecond() != 0 || offset != 0 {
		return errors.New("independently selected UTC whole-second collection epoch required")
	}
	if p.Schema != 1 || !shaPattern.MatchString(p.PlatformSHA256) || !shaPattern.MatchString(p.EnrollmentSHA256) || !shaPattern.MatchString(p.ApplicationSHA256) || !shaPattern.MatchString(p.SelfSHA256) || !shaPattern.MatchString(p.OriginalSeedSHA256) {
		return errors.New("independent scenario input pins required")
	}
	if err := validatePlanCase(p); err != nil {
		return err
	}
	roles := map[string][2]string{"green-primary": {"10.203.11.21", "c11-gp"}, "green-secondary": {"10.203.11.22", "c11-gs"}}
	r, ok := roles[p.Node]
	if !ok || p.Target != r[0] || p.Namespace != r[1] || p.Machine != "task11-"+p.Node || p.NAS != "10.203.11.40" || p.NASNamespace != "c11-nas" || !sessionPattern.MatchString(p.Session) {
		return errors.New("closed green and NAS identities required")
	}
	if p.Scenario == "eap-unenrolled" {
		if p.Node != "green-primary" || len(p.Events) != 0 || p.OutageSeconds != 0 {
			return errors.New("fixed rejection case forbids accounting or outage")
		}
		return nil
	}
	switch p.Scenario {
	case "postgres-outage", "business-outage":
		if p.OutageSeconds < 1 || p.OutageSeconds > 60 {
			return errors.New("outage must be bounded1..60seconds")
		}
	case "native-accounting", "ongoing-baseline", "duplicate-pair", "ha-primary", "ca-continuity":
		if p.OutageSeconds != 0 {
			return errors.New("outage field outside outage scenario")
		}
	default:
		return errors.New("unknown installed scenario")
	}
	if len(p.Events) < 1 || len(p.Events) > 16 {
		return errors.New("bounded independent accounting events required")
	}
	for _, e := range p.Events {
		if (e.Status != 1 && e.Status != 2 && e.Status != 3) || e.Duration > 86400 || e.Upload > 1<<40 || e.Download > 1<<40 || (e.Status == 1 && (e.Duration != 0 || e.Upload != 0 || e.Download != 0)) {
			return errors.New("invalid bounded synthetic event")
		}
	}
	if p.Scenario == "ongoing-baseline" && p.Events[0].Status == 1 {
		return errors.New("ongoing case requires first interim or stop")
	}
	return nil
}
func scenarioSteps(p scenarioPlan) ([]string, error) {
	if err := validatePlan(p); err != nil {
		return nil, err
	}
	prefix := []string{"fresh-active-pair", "freeze-independent-events", "readonly-before"}
	var mid []string
	if p.Scenario == "eap-unenrolled" {
		return []string{"fresh-active-pair", "readonly-before", "authenticated-native-reject", "readonly-after-empty"}, nil
	}
	switch p.Scenario {
	case "postgres-outage":
		mid = []string{"stop-owned-postgres", "traffic-native-response", "start-owned-postgres", "wait-ledger-replay"}
	case "business-outage":
		mid = []string{"intake-unavailable", "traffic-native-response", "reboot-owned-primary", "intake-ready", "wait-original-outbox-replay"}
	case "ha-primary":
		mid = []string{"freeze-primary-continuity", "stop-owned-primary", "peer-native-traffic", "start-owned-primary", "wait-new-boot", "verify-preserved-continuity"}
	case "native-accounting", "ongoing-baseline", "duplicate-pair":
		mid = []string{"traffic-native-response", "wait-ledger"}
	case "ca-continuity":
		return []string{"fresh-original-ca", "genuine-scep-issuance", "genuine-scep-renewal", "readonly-original-issued-rows", "controller-prepare-cutover", "readonly-adopted-issued-rows", "verify-preserved-issued-chain", "controller-deactivate", "genuine-passive-signing-denial"}, nil
	}
	return append(append(prefix, mid...), "readonly-after", "verify-accounting"), nil
}
func validLiveIdentity(v liveIdentity) bool {
	return (v.Machine == "task11-green-primary" || v.Machine == "task11-green-secondary") && v.Root == "/var/lib/cloud8021x-task11/roots/"+v.Machine && machineIDPattern.MatchString(v.MachineID) && bootPattern.MatchString(v.BootID) && shaPattern.MatchString(v.ConfigSHA256) && shaPattern.MatchString(v.ApplicationSHA256) && v.Leader > 1 && v.StartTicks > 0 && v.Namespace > 0 && v.ObservedSequence > 0
}
func sameLiveIdentity(before, after liveIdentity) error {
	if !validLiveIdentity(before) || !validLiveIdentity(after) || after.ObservedSequence <= before.ObservedSequence {
		return errors.New("fresh measured enrolled identity required")
	}
	after.ObservedSequence = before.ObservedSequence
	if !reflect.DeepEqual(before, after) {
		return errors.New("node changed during operation")
	}
	return nil
}
func allowNewAttempt(old *attemptRecord) error {
	if old != nil {
		return errors.New("retained irreversible attempt; reconcile without automatic rerun")
	}
	return nil
}
func verifyContinuity(before, after continuity, oldLeaderRetired bool) error {
	valid := func(v continuity) bool {
		options := "," + v.CollectorOptions + ","
		return (v.Machine == "task11-green-primary" || v.Machine == "task11-green-secondary") && machineIDPattern.MatchString(v.MachineID) && bootPattern.MatchString(v.BootID) && v.Root == "/var/lib/cloud8021x-task11/roots/"+v.Machine && v.Leader > 1 && v.StartTicks > 0 && shaPattern.MatchString(v.ApplicationSHA256) && shaPattern.MatchString(v.ConfigSHA256) && v.CollectorBacking == "/var/lib/cloud-8021x-bootstrap/collector.ext4" && v.CollectorBytes == 512<<20 && v.CollectorDevice > 0 && v.CollectorInode > 0 && v.CollectorFilesystem == "ext4" && strings.Contains(options, ",nodev,") && strings.Contains(options, ",nosuid,") && strings.Contains(options, ",noexec,") && v.Epoch != "" && v.Deployment == "task11-green" && v.WorkersActive
	}
	if !oldLeaderRetired || !valid(before) || !valid(after) || before.BootID == after.BootID || (before.Leader == after.Leader && before.StartTicks == after.StartTicks) {
		return errors.New("actual retired leader/new boot/preserved collector required")
	}
	after.BootID = before.BootID
	after.Leader = before.Leader
	after.StartTicks = before.StartTicks
	if !reflect.DeepEqual(before, after) {
		return errors.New("persistent app/config/epoch/collector changed")
	}
	return nil
}
func verifyAccountingEvidence(e accountingEvidence) error {
	if e.PacketACKs < 1 || !e.LedgerVerified || !shaPattern.MatchString(e.ControllerVerifiedCloudSHA256) || !shaPattern.MatchString(e.IndependentExpectationSHA256) {
		return errors.New("ACK is not independent ledger or delivery proof")
	}
	return nil
}
func validateCAClientPlan(p caClientPlan) error {
	if (p.Blue != "10.203.11.31" && p.Blue != "10.203.11.32") || !fixtureDNSPattern.MatchString(p.DNS) || strings.Contains(p.DNS, "..") || p.Provisioner != "wifi-scep" || p.BrokerTLSName != "localhost" {
		return errors.New("closed original CA/broker endpoint required")
	}
	for _, pin := range []string{p.RootSHA256, p.IntermediateSHA256, p.DecrypterSHA256, p.BrokerCertificateSHA256, p.BrokerTokenSHA256} {
		if !shaPattern.MatchString(pin) {
			return errors.New("original CA/broker input pins required")
		}
	}
	return nil
}
