package sources

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/domain"
)

type verifier struct {
	got []domain.SourceCandidate
	err error
}

func (v verifier) Verify(context.Context, []Binding) ([]domain.SourceCandidate, error) {
	return v.got, v.err
}

type operations struct {
	order []string
	fail  string
	state State
	saved int
}

func (o *operations) Snapshot(context.Context) (Backup, error) {
	o.order = append(o.order, "snapshot")
	return Backup{}, nil
}
func (o *operations) Install(context.Context, Plan) error {
	o.order = append(o.order, "install")
	return nil
}
func (o *operations) Validate(context.Context) error {
	o.order = append(o.order, "validate")
	if o.fail == "validate" {
		return errors.New("failed")
	}
	return nil
}
func (o *operations) Activate(context.Context) error {
	o.order = append(o.order, "activate")
	return nil
}
func (o *operations) Converge(context.Context, Plan) error {
	o.order = append(o.order, "converge")
	if o.fail == "converge" {
		return errors.New("failed")
	}
	return nil
}
func (o *operations) Commit(_ context.Context, s State) error {
	o.order = append(o.order, "commit")
	o.saved++
	o.state = s
	return nil
}
func (o *operations) Rollback(context.Context, Backup) error {
	o.order = append(o.order, "rollback")
	return nil
}
func TestRootRevalidationAndRollback(t *testing.T) {
	now := time.Now()
	candidate := domain.SourceCandidate{ProviderID: "u", SiteID: "pinned", CIDRs: []string{"8.8.8.8/32"}, ObservedAt: domain.Unix(now)}
	cfg := Config{MaxAge: time.Minute, Bindings: []Binding{{ProviderID: "u", ConsoleID: "pinned", ClientID: "nyc", LocationID: "nyc", StaticCIDRs: []string{"10.1.0.0/24"}}}}
	for _, tc := range []struct {
		name     string
		evidence []domain.SourceCandidate
		fail     string
		wantOps  bool
	}{{"fabricated", nil, "", false}, {"wrongsite", []domain.SourceCandidate{{ProviderID: "u", SiteID: "other", CIDRs: candidate.CIDRs, ObservedAt: candidate.ObservedAt}}, "", false}, {"firewall", []domain.SourceCandidate{candidate}, "converge", true}} {
		t.Run(tc.name, func(t *testing.T) {
			o := &operations{fail: tc.fail}
			a := Applier{Config: cfg, Verifier: verifier{got: tc.evidence}, Operations: o, Now: func() time.Time { return now }}
			_, err := a.Apply(context.Background(), []domain.SourceCandidate{candidate}, false)
			if err == nil {
				t.Fatal("unsafe success")
			}
			if o.saved != 0 {
				t.Fatal("failure advanced freshness")
			}
			if tc.wantOps {
				if o.order[len(o.order)-1] != "rollback" {
					t.Fatal(o.order)
				}
			} else if len(o.order) != 0 {
				t.Fatal("mutated before provenance", o.order)
			}
		})
	}
}
func TestDryRunExpiryStaticFallbackOverlapAndOriginalFreshness(t *testing.T) {
	now := time.Now()
	base := domain.SourceCandidate{ProviderID: "u", SiteID: "pinned", CIDRs: []string{"8.8.8.8/32"}, ObservedAt: domain.Unix(now.Add(-10 * time.Second))}
	cfg := Config{MaxAge: time.Minute, Bindings: []Binding{{ProviderID: "u", ConsoleID: "pinned", ClientID: "nyc", LocationID: "nyc", StaticCIDRs: []string{"10.1.0.0/24"}}}}
	o := &operations{}
	a := Applier{Config: cfg, Verifier: verifier{got: []domain.SourceCandidate{base}}, Operations: o, Now: func() time.Time { return now }}
	plan, e := a.Apply(context.Background(), []domain.SourceCandidate{base}, true)
	if e != nil || len(plan.SourceRanges) != 1 || len(o.order) != 1 || o.order[0] != "snapshot" {
		t.Fatalf("dry-run mutated or did not plan %v %+v", e, o)
	}
	if _, e = a.Apply(context.Background(), []domain.SourceCandidate{base}, false); e != nil {
		t.Fatal(e)
	}
	if o.state.Candidates[0].ObservedAt != base.ObservedAt {
		t.Fatal("freshness was reset")
	}
	if !Allowed(cfg, o.state, "nyc", "8.8.8.8", now) || Allowed(cfg, o.state, "nyc", "8.8.8.8", now.Add(time.Hour)) || !Allowed(cfg, o.state, "nyc", "10.1.0.5", now.Add(time.Hour)) {
		t.Fatal("dynamic TTL or static fallback broken")
	}
	for _, cidr := range []string{"0.0.0.0/0", "8.8.8.0/24", "127.0.0.1/32", "224.0.0.1/32", "10.0.0.1/32", "192.0.2.1/32"} {
		bad := base
		bad.CIDRs = []string{cidr}
		if _, e = a.Apply(context.Background(), []domain.SourceCandidate{bad}, true); e == nil {
			t.Fatal("bad source accepted", cidr)
		}
	}
	a.Config.Bindings = append(a.Config.Bindings, Binding{ClientID: "other", LocationID: "other", StaticCIDRs: []string{"8.8.8.0/24"}})
	if _, e = a.Apply(context.Background(), []domain.SourceCandidate{base}, true); e == nil {
		t.Fatal("cross-client overlap accepted")
	}
}
func TestVerifierStaleFailedAndCandidateTimestampRecheck(t *testing.T) {
	now := time.Now()
	c := domain.SourceCandidate{ProviderID: "u", SiteID: "c", CIDRs: []string{"8.8.8.8/32"}, ObservedAt: domain.Unix(now)}
	cfg := Config{MaxAge: time.Minute, Bindings: []Binding{{ProviderID: "u", ConsoleID: "c", ClientID: "client", LocationID: "site"}}}
	stale := c
	stale.ObservedAt = domain.Unix(now.Add(-time.Hour))
	for _, v := range []verifier{{got: []domain.SourceCandidate{stale}}, {err: errors.New("sentinel")}} {
		o := &operations{}
		a := Applier{Config: cfg, Verifier: v, Operations: o, Now: func() time.Time { return now }}
		if _, e := a.Apply(context.Background(), []domain.SourceCandidate{c}, false); e == nil || len(o.order) != 0 {
			t.Fatal("invalid root evidence mutated")
		}
	}
	ticks := 0
	o := &operations{}
	a := Applier{Config: cfg, Verifier: verifier{got: []domain.SourceCandidate{c}}, Operations: o, Now: func() time.Time {
		ticks++
		if ticks >= 3 {
			return now.Add(time.Hour)
		}
		return now
	}}
	if _, e := a.Apply(context.Background(), []domain.SourceCandidate{c}, false); e == nil || o.saved != 0 || o.order[len(o.order)-1] != "rollback" {
		t.Fatal("expiry during convergence freshened state")
	}
}
