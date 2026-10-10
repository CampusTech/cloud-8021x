package sources

import (
	"testing"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/domain"
)

func TestStaticIPv6IsCanonicalAndCannotBroadenDiscovery(t *testing.T) {
	cfg := Config{MaxAge: time.Minute, Bindings: []Binding{{ClientID: "office", LocationID: "nyc", StaticCIDRs: []string{"2001:db8::/64"}}}}
	if e := cfg.Validate(); e != nil {
		t.Fatal(e)
	}
	for _, prefix := range []string{"::/0", "2001:0db8::/64", "2001:db8::1/64", "fe80::%en0/64", "::ffff:192.0.2.0/120"} {
		cfg.Bindings[0].StaticCIDRs = []string{prefix}
		if e := cfg.Validate(); e == nil {
			t.Fatal("unsafe static IPv6", prefix)
		}
	}
	cfg.Bindings[0].StaticCIDRs = []string{"2001:db8::/64"}
	cfg.Bindings = append(cfg.Bindings, Binding{ClientID: "other", LocationID: "other", StaticCIDRs: []string{"2001:db8::/80"}})
	if e := cfg.Validate(); e == nil {
		t.Fatal("ambiguous static IPv6")
	}
	cfg.Bindings = cfg.Bindings[:1]
	cfg.Bindings[0].ProviderID = "p"
	cfg.Bindings[0].ConsoleID = "c"
	candidate := domain.SourceCandidate{ProviderID: "p", SiteID: "c", ObservedAt: domain.Unix(time.Now()), CIDRs: []string{"2001:db8::1/128"}}
	if _, e := canonical([]domain.SourceCandidate{candidate}, cfg, time.Now()); e == nil {
		t.Fatal("broadened dynamic discovery to IPv6")
	}
	cfg.Bindings[0].StaticCIDRs = append(cfg.Bindings[0].StaticCIDRs, "8.8.8.0/24")
	cfg.Bindings = append(cfg.Bindings, Binding{ClientID: "other", LocationID: "other", ProviderID: "p", ConsoleID: "d"})
	if _, e := makePlan(cfg, map[string]domain.SourceCandidate{key("p", "d"): {ProviderID: "p", SiteID: "d", ObservedAt: candidate.ObservedAt, CIDRs: []string{"8.8.8.8/32"}}}); e == nil {
		t.Fatal("dynamic source overlaps other static client")
	}
}
