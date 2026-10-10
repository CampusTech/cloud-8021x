package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/CampusTech/cloud-8021x/internal/config"
	"gopkg.in/yaml.v3"
)

func TestPrepareRequiresStagedReceiptKeysMatchPhysicalEnrollment(t *testing.T) {
	in := producerFixture(t)
	var enrollment producerEnrollment
	if err := json.Unmarshal(in.Enrollment, &enrollment); err != nil {
		t.Fatal(err)
	}
	pins := map[string]string{
		"blue-primary":    strings.Repeat("1", 64),
		"blue-secondary":  strings.Repeat("2", 64),
		"green-primary":   strings.Repeat("3", 64),
		"green-secondary": strings.Repeat("4", 64),
	}
	// Match the genuine keys lifecycle: platform inventory retains its initial
	// candidate hashes, while keys freezes all four public keys into each staged
	// role config and enrolls the resulting final config hashes.
	for _, name := range []string{"blue-primary", "blue-secondary", "green-primary", "green-secondary"} {
		c, err := config.Decode(bytes.NewReader(in.Configs[name]))
		if err != nil {
			t.Fatal(err)
		}
		c.Deployment.SourcePrimaryKey = pins["blue-primary"]
		c.Deployment.SourceSecondaryKey = pins["blue-secondary"]
		c.Deployment.DestinationPrimaryKey = pins["green-primary"]
		c.Deployment.DestinationSecondaryKey = pins["green-secondary"]
		if err := c.ValidateHandoffPins(); err != nil {
			t.Fatalf("valid four-key setup rejected: %v", err)
		}
		raw, err := yaml.Marshal(c)
		if err != nil {
			t.Fatal(err)
		}
		in.Configs[name] = raw
		node := enrollment.Nodes[name]
		node.Pin = pins[name]
		node.ConfigSHA256 = digestBytes(raw)
		enrollment.Nodes[name] = node
	}
	var err error
	in.Enrollment, err = json.Marshal(enrollment)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := prepareNASBundle(in); err != nil {
		t.Fatalf("genuine matched staged receipt-key bindings rejected: %v", err)
	}
	t.Log("valid matched distinct physical receipt keys accepted")

	// Change only one physically enrolled public key. Every staged config and
	// its final enrolled config hash remains unchanged and names the old key.
	node := enrollment.Nodes["blue-primary"]
	node.Pin = strings.Repeat("5", 64)
	enrollment.Nodes["blue-primary"] = node
	in.Enrollment, err = json.Marshal(enrollment)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := prepareNASBundle(in); err == nil {
		t.Fatal("changed physical blue-primary receipt key accepted while all staged configs bind the original key")
	}
}
