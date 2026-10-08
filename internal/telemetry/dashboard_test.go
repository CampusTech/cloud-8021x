package telemetry

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestDashboardSharedClusterGaugesNeverSumNodeReporters(t *testing.T) {
	raw, e := os.ReadFile("../../docs/telemetry/daemon-dashboard.json")
	if e != nil {
		t.Fatal(e)
	}
	var d struct {
		Widgets []struct {
			Definition struct {
				Requests []struct {
					Q string `json:"q"`
				} `json:"requests"`
			} `json:"definition"`
		} `json:"widgets"`
	}
	if e = json.Unmarshal(raw, &d); e != nil {
		t.Fatal(e)
	}
	shared := 0
	for _, w := range d.Widgets {
		for _, r := range w.Definition.Requests {
			if strings.Contains(r.Q, "scope:shared") {
				shared++
				if !strings.HasPrefix(r.Q, "max:") || !strings.HasSuffix(r.Q, " by {cluster}") || strings.Contains(r.Q, "host") {
					t.Fatal("duplicated shared total", r.Q)
				}
			}
		}
	}
	if shared != 6 {
		t.Fatal("shared gauge coverage", shared)
	}
}
