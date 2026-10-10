package main

import (
	"bytes"
	"time"

	"encoding/json"
	"testing"

	"github.com/CampusTech/cloud-8021x/internal/config"
	"gopkg.in/yaml.v3"
)

// The runtime assembler stages each proposed green role configuration
// identically into blue and green. Blue's installed source configuration is a
// separate /etc/cloud-8021x/config.yaml candidate. Producer reads the staged
// artifact, so it must not interpret it as blue's installed source config.
func TestPrepareAdmitsActualSharedStagedRoleConfigs(t *testing.T) {
	in := producerFixture(t)
	var enrollment producerEnrollment
	if err := json.Unmarshal(in.Enrollment, &enrollment); err != nil {
		t.Fatal(err)
	}
	for _, role := range []string{"primary", "secondary"} {
		blue, green := "blue-"+role, "green-"+role
		in.Configs[blue] = append([]byte(nil), in.Configs[green]...)
		node := enrollment.Nodes[blue]
		node.ConfigSHA256 = digestBytes(in.Configs[blue])
		enrollment.Nodes[blue] = node
	}
	in.Enrollment, _ = json.Marshal(enrollment)
	if _, err := prepareNASBundle(in); err != nil {
		t.Fatalf("real assembler staged-blue configuration refused: %v", err)
	}
}

func TestPrepareKeepsBluePhysicalAndStagedAuthoritiesIndependent(t *testing.T) {
	for _, what := range []string{"physical-hostname", "staged-hostname", "staged-class-key", "staged-epoch", "empty-keys", "duplicate-keys", "source-id", "source-primary", "source-secondary"} {
		t.Run(what, func(t *testing.T) {
			in := producerFixture(t)
			var enrollment producerEnrollment
			if err := json.Unmarshal(in.Enrollment, &enrollment); err != nil {
				t.Fatal(err)
			}
			node := enrollment.Nodes["blue-primary"]
			if what == "physical-hostname" {
				node.Hostname = "task11-green-primary"
			} else {
				c, err := config.Decode(bytes.NewReader(in.Configs["blue-primary"]))
				if err != nil {
					t.Fatal(err)
				}
				switch what {
				case "staged-hostname":
					c.Hostname = "task11-blue-primary"
				case "staged-class-key":
					c.Policy.ClassSigningKey = config.SecretRef{File: "/run/radius-accounting-key"}
				case "staged-epoch":
					c.Deployment.CollectionEpoch = c.Deployment.CollectionEpoch.Add(time.Second)
				case "empty-keys":
					c.Deployment.SourcePrimaryKey = ""
				case "duplicate-keys":
					c.Deployment.SourcePrimaryKey = c.Deployment.DestinationPrimaryKey
				case "source-id":
					c.Deployment.SourceID = "foreign-blue"
				case "source-primary":
					c.Deployment.SourcePrimary = "foreign-blue-primary"
				case "source-secondary":
					c.Deployment.SourceSecondary = "foreign-blue-secondary"
				}
				raw, err := yaml.Marshal(c)
				if err != nil {
					t.Fatal(err)
				}
				in.Configs["blue-primary"] = raw
				node.ConfigSHA256 = digestBytes(raw)
			}
			enrollment.Nodes["blue-primary"] = node
			in.Enrollment, _ = json.Marshal(enrollment)
			if _, err := prepareNASBundle(in); err == nil {
				t.Fatal("physical or staged authority substitution accepted")
			}
		})
	}
}
