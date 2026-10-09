package sources

import "testing"

func TestParallelFirewallTargetCannotAddressBlue(t *testing.T) {
	for _, node := range []string{"radius-primary", "blue-primary", "green-secondary", "green-primary/../../blue"} {
		target := FirewallTarget{Project: "fixture-project", Node: node, Network: "fixed", Deployment: "green", Role: "radius-primary"}
		if target.Validate() == nil {
			t.Fatalf("accepted mismatched green firewall %s", node)
		}
	}
	if err := (FirewallTarget{Project: "fixture-project", Node: "green-primary", Network: "fixed", Deployment: "green", Role: "radius-primary"}).Validate(); err != nil {
		t.Fatal(err)
	}
	if err := (FirewallTarget{Project: "fixture-project", Node: "radius-primary", Network: "fixed"}).Validate(); err != nil {
		t.Fatal(err)
	}
}
