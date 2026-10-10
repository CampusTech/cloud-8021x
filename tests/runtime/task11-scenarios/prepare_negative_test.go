package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/CampusTech/cloud-8021x/internal/config"
	"gopkg.in/yaml.v3"
)

func TestProducerIndependentPinsAndFixedExpectationsFailClosed(t *testing.T) {
	original := producerFixture(t)
	clone := func() producerInputs {
		in := original
		in.Files = map[string][]byte{}
		in.Configs = map[string][]byte{}
		for n, b := range original.Files {
			in.Files[n] = bytes.Clone(b)
		}
		for n, b := range original.Configs {
			in.Configs[n] = bytes.Clone(b)
		}
		return in
	}
	for name, change := range map[string]func(*producerInputs){
		"original-client-substitution": func(i *producerInputs) { i.Files["nas/client.key"] = []byte("foreign") },
		"original20-substitution":      func(i *producerInputs) { i.Files["source/run/radius-accounting-key"] = []byte(strings.Repeat("x", 64)) },
		"enrollment-application": func(i *producerInputs) {
			var e producerEnrollment
			_ = json.Unmarshal(i.Enrollment, &e)
			e.ApplicationSHA256 = strings.Repeat("f", 64)
			i.Enrollment, _ = json.Marshal(e)
		},
		"physical-machine": func(i *producerInputs) {
			var e producerEnrollment
			_ = json.Unmarshal(i.Enrollment, &e)
			n := e.Nodes["green-primary"]
			n.MachineID = strings.Repeat("f", 32)
			e.Nodes["green-primary"] = n
			i.Enrollment, _ = json.Marshal(e)
		},
		"missing-seventh-helper": func(i *producerInputs) {
			var p producerPlatform
			_ = json.Unmarshal(i.Platform, &p)
			delete(p.Helpers, "task11-scenarios")
			i.Platform, _ = json.Marshal(p)
		},
		"unknown-platform-field": func(i *producerInputs) {
			var p map[string]any
			_ = json.Unmarshal(i.PlatformPlan, &p)
			p["EndpointOverride"] = "unsafe"
			i.PlatformPlan, _ = json.Marshal(p)
			var f producerPlatform
			_ = json.Unmarshal(i.Platform, &f)
			f.PlanSHA256 = digestBytes(i.PlatformPlan)
			i.Platform, _ = json.Marshal(f)
		},
		"post-phase-enrollment": func(i *producerInputs) {
			var e producerEnrollment
			_ = json.Unmarshal(i.Enrollment, &e)
			e.Passive.Manifests = map[string]string{"green-primary-prepared": strings.Repeat("f", 64)}
			i.Enrollment, _ = json.Marshal(e)
		},
	} {
		t.Run(name, func(t *testing.T) {
			in := clone()
			change(&in)
			if _, e := prepareNASBundle(in); e == nil {
				t.Fatal("substituted authority accepted")
			}
		})
	}
	for _, what := range []string{"vlan", "broker", "epoch", "class-key", "server-dns"} {
		t.Run(what, func(t *testing.T) {
			in := clone()
			c, e := config.Decode(bytes.NewReader(in.Configs["green-primary"]))
			if e != nil {
				t.Fatal(e)
			}
			switch what {
			case "vlan":
				c.Policy.Rules[0].VLAN = 121
			case "broker":
				c.Listeners.Broker.SCEPURL = "https://rsa.task11.test:8443/scep/wifi-scep"
			case "class-key":
				c.Policy.ClassSigningKey = config.SecretRef{File: "/run/unrelated-class-key"}
			case "server-dns":
				c.Bootstrap.ServerDNS = "foreign.task11.test"
			case "epoch":
				c.Deployment.CollectionEpoch = c.Deployment.CollectionEpoch.Add(1000000000)
			}
			raw, e := yaml.Marshal(c)
			if e != nil {
				t.Fatal(e)
			}
			in.Configs["green-primary"] = raw
			var en producerEnrollment
			_ = json.Unmarshal(in.Enrollment, &en)
			n := en.Nodes["green-primary"]
			n.ConfigSHA256 = digestBytes(raw)
			en.Nodes["green-primary"] = n
			in.Enrollment, _ = json.Marshal(en)
			if _, e = prepareNASBundle(in); e == nil {
				t.Fatal("learned expectation from changed config")
			}
		})
	}
}
