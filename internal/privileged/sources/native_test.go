package sources

import (
	"strings"
	"testing"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/domain"
)

func TestNativeDynamicClientsKeepProtectedConfigurationAndStableAge(t *testing.T) {
	now := time.Unix(1791453600, 0)
	cfg := Config{MaxAge: 15 * time.Minute, Bindings: []Binding{{ProviderID: "u", ConsoleID: "console", ClientID: "office", LocationID: "nyc", Medium: "wifi", SecretFile: "/private/key", StaticCIDRs: []string{"10.0.0.0/24"}}}}
	rows := map[string]domain.SourceCandidate{key("u", "console"): {ProviderID: "u", SiteID: "console", ObservedAt: domain.Unix(now), CIDRs: []string{"8.8.8.8/32"}}}
	p, e := makePlan(cfg, rows)
	if e != nil {
		t.Fatal(e)
	}
	o, _, _ := fixtureOps(t)
	data, e := o.render(p)
	if e != nil {
		t.Fatal(e)
	}
	for _, want := range []string{"c8021x_source_kind = dynamic", "c8021x_max_age = 900", "c8021x_client_hash = " + clientHash("office"), "c8021x_config = " + cfg.Identity()} {
		if !strings.Contains(string(data), want) {
			t.Fatal("missing", want, string(data))
		}
	}
}
