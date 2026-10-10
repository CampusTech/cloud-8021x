package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"reflect"
	"strings"

	"github.com/CampusTech/cloud-8021x/internal/config"
	seed "github.com/CampusTech/cloud-8021x/tests/runtime/task11-assembly-seed/contract"
)

func validateProducerInputs(in producerInputs) (producerValidated, error) {
	var v producerValidated
	if strictJSON(in.Input, 64<<10, &v.Input) != nil || v.Input.Validate() != nil || v.Input.ServerDNS != nativeServerDNS || strictJSON(in.Platform, 64<<10, &v.Platform) != nil || strictJSON(in.Enrollment, 64<<10, &v.Enrollment) != nil {
		return v, errors.New("protected finalized input/platform/enrollment invalid")
	}
	i, p, e := v.Input, v.Platform, v.Enrollment
	if p.Schema != 1 || e.Schema != 1 || p.InputSHA256 != digestBytes(in.Input) || !shaPattern.MatchString(p.CandidateSHA256) || digestBytes(in.PlatformPlan) != p.PlanSHA256 || !shaPattern.MatchString(e.ApplicationSHA256) || !shaPattern.MatchString(e.ControllerSHA256) || e.Passive.OriginalSeedSHA256 != i.OriginalManifestSHA256 || e.Cloud.InstalledSeedSHA256 != i.InstalledSeedSHA256 || e.Cloud.OriginalStateSHA256 != i.OriginalStateSHA256 || len(e.Passive.Manifests) != 0 {
		return v, errors.New("independent original/platform/physical pins differ")
	}
	var pp map[string]json.RawMessage
	if strictJSON(in.PlatformPlan, 64<<10, &pp) != nil {
		return v, errors.New("bounded platform plan invalid")
	}
	allowed := strings.Fields("Schema InputSHA256 CandidateSHA256 PackageManifestSHA256 BaselineSHA256 LowerManifestSHA256 ApplicationSourceSHA ApplicationSHA256 ControllerSHA256 ObserverSHA256 CloudSHA256 ObserverSourceSHA256 CloudSourceSHA256 PrimitiveSeedSHA256 PrimitiveExpectedSHA256 ControllerUnitSHA256 PrimitiveInputSHA256 BluePlanSHA256 Helpers Tools Nodes Flows Budget LoopDevices")
	for key := range pp {
		if !producerHas(allowed, key) {
			return v, errors.New("unknown platform plan field")
		}
	}
	var schema int
	if json.Unmarshal(pp["Schema"], &schema) != nil || schema != 1 {
		return v, errors.New("platform schema differs")
	}
	for key, want := range map[string]string{"InputSHA256": p.InputSHA256, "CandidateSHA256": p.CandidateSHA256, "ApplicationSHA256": e.ApplicationSHA256, "ControllerSHA256": e.ControllerSHA256} {
		var got string
		if json.Unmarshal(pp[key], &got) != nil || got != want {
			return v, errors.New("platform authority differs")
		}
	}
	var helpers map[string]producerPin
	if strictJSON(pp["Helpers"], 16<<10, &helpers) != nil || len(helpers) != 7 || len(p.Helpers) != 7 {
		return v, errors.New("seven fixed helpers required")
	}
	for _, name := range []string{"task11-acceptance", "task11-passive-audit", "task11-cloud-contract", "task11-assembly-seed", "task11-blue-migration", "task11-systemd-fixture", "task11-scenarios"} {
		a, b := helpers[name], p.Helpers[name]
		if a.Path != outerControl+"/public/"+name || b.Path != "/usr/local/libexec/"+name || !shaPattern.MatchString(a.SHA256) || a.SHA256 != b.SHA256 {
			return v, errors.New("fixed helper authority differs")
		}
	}
	if helpers["task11-acceptance"].SHA256 != e.ControllerSHA256 {
		return v, errors.New("controller authority differs")
	}
	names := []string{"blue-primary", "blue-secondary", "green-primary", "green-secondary"}
	nets := []string{"c11-bp", "c11-bs", "c11-gp", "c11-gs"}
	ips := []string{"10.203.11.31", "10.203.11.32", "10.203.11.21", "10.203.11.22"}
	if len(p.Nodes) != 4 || len(e.Nodes) != 4 || len(in.Configs) != 4 {
		return v, errors.New("four physical configs required")
	}
	seen := map[string]bool{}
	for x, name := range names {
		n, en := p.Nodes[x], e.Nodes[name]
		if n.Name != name || n.Machine != "task11-"+name || n.Root != "/var/lib/cloud8021x-task11/roots/task11-"+name || n.Namespace != nets[x] || n.Address != ips[x] || !machineIDPattern.MatchString(n.MachineID) || seen[n.MachineID] || en.MachineID != n.MachineID || en.Hostname != n.Machine || !shaPattern.MatchString(en.Pin) || !shaPattern.MatchString(n.ConfigSHA256) || digestBytes(in.Configs[name]) != en.ConfigSHA256 {
			return v, errors.New("physical/config enrollment differs")
		}
		seen[n.MachineID] = true
		c, err := config.Decode(bytes.NewReader(in.Configs[name]))
		if err != nil || c.ValidateHandoffPins() != nil || producerConfig(c, i, name) != nil {
			return v, errors.New("fixed shipping config expectations differ")
		}
		d := c.Deployment
		if d.SourcePrimaryKey != e.Nodes["blue-primary"].Pin || d.SourceSecondaryKey != e.Nodes["blue-secondary"].Pin || d.DestinationPrimaryKey != e.Nodes["green-primary"].Pin || d.DestinationSecondaryKey != e.Nodes["green-secondary"].Pin {
			return v, errors.New("staged receipt keys differ from physical enrollment")
		}
	}
	expectedAux := []producerAux{{"api", "/var/lib/cloud8021x-task11/aux/api", "c11-api", "10.203.11.10"}, {"pg", "/var/lib/cloud8021x-task11/aux/pg", "c11-pg", "10.203.11.11"}, {"nas", "/var/lib/cloud8021x-task11/aux/nas", "c11-nas", "10.203.11.40"}}
	if !reflect.DeepEqual(p.Auxiliary, expectedAux) {
		return v, errors.New("closed auxiliary identity differs")
	}
	var manifest producerManifest
	if strictJSON(in.Manifest, 16<<10, &manifest) != nil || manifest.Schema != 1 || len(manifest.Files) != len(producerOriginalNames) || digestBytes(in.Manifest) != i.OriginalManifestSHA256 {
		return v, errors.New("exact original20 manifest required")
	}
	for _, name := range producerOriginalNames {
		b := in.Files[name]
		if len(b) == 0 || len(b) > 32<<20 || digestBytes(b) != manifest.Files[name] || i.Files[name] != manifest.Files[name] {
			return v, errors.New("original preserved bytes differ")
		}
	}
	for _, name := range producerAllMaterialPaths() {
		if len(in.Files[name]) == 0 || len(in.Files[name]) > 64<<10 || digestBytes(in.Files[name]) != i.Files[name] {
			return v, errors.New("independently finalized NAS bytes differ")
		}
	}
	if strictJSON(in.Files["spec.json"], 64<<10, &v.Spec) != nil || v.Spec.Remote == nil || v.Spec.Project != i.Project || v.Spec.ECDNS != i.ECDNS || v.Spec.RSADNS != i.RSADNS || v.Spec.ServerDNS != nativeServerDNS || !v.Spec.ObservedAt.Equal(i.ObservedAt) || v.Spec.Remote.ApplicationSHA256 != e.ApplicationSHA256 {
		return v, errors.New("original fixed seed authority differs")
	}
	return v, nil
}
func producerHas(set []string, name string) bool {
	for _, s := range set {
		if s == name {
			return true
		}
	}
	return false
}
func producerConfig(c config.Config, i seed.Input, name string) error {
	// All four physical nodes stage the proposed green role configuration.
	// Blue installed source configuration is a separate preserved candidate.
	stagedHostname := "task11-green-" + strings.TrimPrefix(strings.TrimPrefix(name, "blue-"), "green-")
	classFile := "/run/cloud-8021x/credentials/accounting-class-key"
	if c.Policy.ClassSigningKey.File != classFile || c.Bootstrap.ServerDNS != nativeServerDNS || c.Bootstrap.ECDNS != i.ECDNS || c.Bootstrap.RSADNS != i.RSADNS || c.CA.URL != "https://"+i.ECDNS+":8443" {
		return errors.New("preserved native/CA/Class authority differs")
	}
	wantRules := []config.VLANRule{{GroupID: "fleet:1", LocationID: "task11", VLAN: 120}}
	wantClients := []config.RadiusClient{{ID: "task11-nas", LocationID: "task11", CIDRs: []string{"10.203.11.40/32"}, Secret: config.SecretRef{File: "/run/cloud-8021x-root/radius-task11-secret"}, Medium: "wifi", SignalingProfile: "unifi-numeric"}}
	if c.Hostname != stagedHostname || !reflect.DeepEqual(c.Policy.Rules, wantRules) || !reflect.DeepEqual(c.RadiusClients, wantClients) || !c.Listeners.Broker.Enabled || c.Listeners.Broker.Address != "0.0.0.0:9081" || c.Listeners.Broker.Username != "fleet" || c.Listeners.Broker.SCEPURL != "https://"+i.RSADNS+":8444/scep/wifi-scep" || c.Listeners.Broker.Provisioner != "wifi-scep" || c.Listeners.Broker.Token.File != "/run/cloud-8021x/credentials/scep-broker-token" {
		return errors.New("fixed NAS policy/broker expectations differ")
	}
	if c.Deployment.SourceID != "task11-blue" || c.Deployment.SourcePrimary != "task11-blue-primary" || c.Deployment.SourceSecondary != "task11-blue-secondary" || c.Deployment.Mode != "parallel" || c.Deployment.ID != "task11-green" || c.Deployment.Instance != stagedHostname || !c.Deployment.CollectionEpoch.Equal(i.CollectionEpoch) {
		return errors.New("configured immutable collection epoch differs")
	}
	return nil
}
