package sources

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/domain"
)

func TestFreshnessRefreshCommitsProofWithoutRadiusRestart(t *testing.T) {
	o, r, _ := fixtureOps(t)
	now := time.Now()
	cfg := Config{MaxAge: time.Minute, Bindings: []Binding{{ProviderID: "u", ConsoleID: "console", ClientID: "office", LocationID: "nyc", Medium: "wifi", SecretFile: "fixed"}}}
	c := domain.SourceCandidate{ProviderID: "u", SiteID: "console", CIDRs: []string{"8.8.8.8/32"}, ObservedAt: domain.Unix(now.Add(-20 * time.Second))}
	apply := func() error {
		a := Applier{Config: cfg, Verifier: verifier{got: []domain.SourceCandidate{c}}, Operations: o, Now: func() time.Time { return now }}
		_, e := a.Apply(context.Background(), []domain.SourceCandidate{c}, false)
		return e
	}
	if e := apply(); e != nil {
		t.Fatal(e)
	}
	old, e := os.ReadFile(filepath.Join(o.proofPath, "current"))
	if e != nil {
		t.Fatal(e)
	}
	starts := r.activate
	c.ObservedAt = domain.Unix(now.Add(-5 * time.Second))
	if e = apply(); e != nil {
		t.Fatal(e)
	}
	current, e := os.ReadFile(filepath.Join(o.proofPath, "current"))
	if e != nil {
		t.Fatal(e)
	}
	if string(old) == string(current) || r.activate != starts {
		t.Fatalf("refresh pointer=%q old=%q restarts=%d want=%d", current, old, r.activate, starts)
	}
	p, e := makePlan(cfg, map[string]domain.SourceCandidate{key("u", "console"): c})
	if e != nil {
		t.Fatal(e)
	}
	if e = o.verifyProof(p, string(current)); e != nil {
		t.Fatal(e)
	}
	// Failed validation must not publish a new observation or restart unchanged clients.
	c.ObservedAt = domain.Unix(now.Add(-time.Second))
	r.fail = true
	if e = apply(); e == nil {
		t.Fatal("failed validation accepted")
	}
	after, _ := os.ReadFile(filepath.Join(o.proofPath, "current"))
	if string(after) != string(current) || r.activate != starts {
		t.Fatal("failed refresh freshened or restarted")
	}
}

func TestProofReconciliationRejectsAlteredOriginalMtime(t *testing.T) {
	o, _, _ := fixtureOps(t)
	now := time.Now()
	cfg := Config{MaxAge: time.Minute, Bindings: []Binding{{ProviderID: "u", ConsoleID: "console", ClientID: "office", LocationID: "nyc", Medium: "wifi", SecretFile: "fixed"}}}
	c := domain.SourceCandidate{ProviderID: "u", SiteID: "console", CIDRs: []string{"8.8.8.8/32"}, ObservedAt: domain.Unix(now.Add(-5 * time.Second))}
	a := Applier{Config: cfg, Verifier: verifier{got: []domain.SourceCandidate{c}}, Operations: o}
	if _, e := a.Apply(context.Background(), []domain.SourceCandidate{c}, false); e != nil {
		t.Fatal(e)
	}
	if _, e := a.ReconcileApplied(context.Background(), []domain.SourceCandidate{c}); e != nil {
		t.Fatal(e)
	}
	pointer, _ := os.ReadFile(filepath.Join(o.proofPath, "current"))
	marker := filepath.Join(o.proofPath, string(pointer), cfg.Identity(), clientHash("office"), "8.8.8.8")
	if e := os.Chtimes(marker, now, now); e != nil {
		t.Fatal(e)
	}
	if _, e := a.ReconcileApplied(context.Background(), []domain.SourceCandidate{c}); e == nil {
		t.Fatal("reconciliation accepted freshened proof")
	}
}

func TestProofRetentionPreservesCurrentPreviousAndUnresolved(t *testing.T) {
	o, _, _ := fixtureOps(t)
	now := time.Now()
	cfg := Config{MaxAge: time.Minute, Bindings: []Binding{{ProviderID: "u", ConsoleID: "console", ClientID: "office", LocationID: "nyc", Medium: "wifi", SecretFile: "fixed"}}}
	var generations []string
	for _, seconds := range []int{20, 15, 10, 5} {
		candidate := domain.SourceCandidate{ProviderID: "u", SiteID: "console", CIDRs: []string{"8.8.8.8/32"}, ObservedAt: domain.Unix(now.Add(-time.Duration(seconds) * time.Second))}
		applier := Applier{Config: cfg, Verifier: verifier{got: []domain.SourceCandidate{candidate}}, Operations: o, Now: func() time.Time { return now }}
		if _, err := applier.Apply(context.Background(), []domain.SourceCandidate{candidate}, false); err != nil {
			t.Fatal(err)
		}
		current, err := os.ReadFile(filepath.Join(o.proofPath, "current"))
		if err != nil {
			t.Fatal(err)
		}
		generations = append(generations, string(current))
	}
	o.RetainedProofs = func(context.Context) ([]string, error) { return []string{generations[1]}, nil }
	marker := filepath.Join(o.proofPath, generations[2], cfg.Identity(), clientHash("office"), "8.8.8.8")
	before, err := os.Stat(marker)
	if err != nil {
		t.Fatal(err)
	}
	if err = o.PrepareRetention(context.Background()); err != nil {
		t.Fatal(err)
	}
	for i, generation := range generations {
		_, err := os.Stat(filepath.Join(o.proofPath, generation))
		if i == 0 && !os.IsNotExist(err) {
			t.Fatal("unreferenced generation retained")
		}
		if i > 0 && err != nil {
			t.Fatal("referenced generation deleted", i, err)
		}
	}
	after, err := os.Stat(marker)
	if err != nil || !before.ModTime().Equal(after.ModTime()) {
		t.Fatal("retention refreshed original proof")
	}
}
