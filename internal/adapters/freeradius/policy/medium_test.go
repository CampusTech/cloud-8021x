package policy

import (
	"context"
	"testing"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/accounting/binding"
)

func TestOnlyUnambiguousWirelessPortGetsVLAN(t *testing.T) {
	for _, ports := range [][]string{nil, {"15"}, {"19", "19"}, {"19", "15"}, {"unknown"}, {"19"}} {
		s, r, _ := setup(t)
		r.NASPortTypes = ports
		result, err := s.Decide(context.Background(), r)
		if err != nil {
			t.Fatal(err)
		}
		wireless := len(ports) == 1 && ports[0] == "19"
		if (result.Decision.VLAN != nil) != wireless {
			t.Fatalf("port types %v VLAN %v", ports, result.Decision.VLAN)
		}
		identity := binding.Verify(s.options.ClassKey, []string{result.Class}, "nyc", r.CallingStations, time.Now(), binding.MaxAge)
		if identity == nil || (identity.VLAN != nil) != wireless {
			t.Fatalf("signed identity does not preserve opt-out: %v", identity)
		}
	}
}
