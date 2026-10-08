package sources

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/domain"
	"github.com/CampusTech/cloud-8021x/internal/network"
)

type radius struct {
	validate, activate, health int
	fail                       bool
}

func (r *radius) Validate(context.Context) error {
	r.validate++
	if r.fail {
		r.fail = false
		return errors.New("SENTINEL secret")
	}
	return nil
}
func (r *radius) Activate(context.Context) error { r.activate++; return nil }
func (r *radius) Healthy(context.Context) error  { r.health++; return nil }

type firewall struct {
	rule    FirewallRule
	patches []FirewallState
	pending *FirewallState
	fail    bool
	never   bool
}

func (f *firewall) Read(context.Context) (FirewallRule, error) {
	if f.pending != nil && !f.never {
		f.rule.SourceRanges = f.pending.SourceRanges
		f.rule.Disabled = f.pending.Disabled
		f.pending = nil
	}
	return f.rule, nil
}
func (f *firewall) Patch(_ context.Context, s FirewallState) error {
	f.patches = append(f.patches, s)
	if f.fail {
		f.fail = false
		return errors.New("SENTINEL secret")
	}
	copy := s
	f.pending = &copy
	return nil
}

type secrets struct{}

func (secrets) ReadSecret(string) ([]byte, error) { return []byte(strings.Repeat("a", 32)), nil }
func fixtureOps(t *testing.T) (*FileOperations, *radius, *firewall) {
	t.Helper()
	dir, e := filepath.EvalSymlinks(t.TempDir())
	if e == nil {
		e = os.Chmod(dir, 0700)
	}
	if e != nil {
		t.Fatal(e)
	}
	r := &radius{}
	f := &firewall{rule: FirewallRule{Name: "allow-radius-primary-discovered", Network: "pinned-network", Direction: "INGRESS", TargetTags: []string{"radius-primary"}, Allowed: []Port{{Protocol: "udp", Ports: []string{"1812", "1813"}}}, SourceRanges: []string{"9.9.9.9/32"}}}
	o, e := NewFileOperations(r, f, FirewallTarget{Project: "synthetic-project", Node: "radius-primary", Network: "pinned-network"}, secrets{})
	if e != nil {
		t.Fatal(e)
	}
	o.clientsPath = filepath.Join(dir, "clients")
	o.statePath = filepath.Join(dir, "state")
	o.poll = time.Millisecond
	if e = network.WritePrivate(o.clientsPath, []byte("previous-clients")); e != nil {
		t.Fatal(e)
	}
	if e = network.WritePublished(o.statePath, []byte(`{"Candidates":[]}`)); e != nil {
		t.Fatal(e)
	}
	return o, r, f
}
func TestActualFilesRollbackAndFixedFirewallConvergence(t *testing.T) {
	for _, fail := range []string{"validate", "firewall", "none"} {
		t.Run(fail, func(t *testing.T) {
			o, r, f := fixtureOps(t)
			oldRule := f.rule
			now := time.Now()
			c := domain.SourceCandidate{ProviderID: "u", SiteID: "console", CIDRs: []string{"8.8.8.8/32"}, ObservedAt: domain.Unix(now.Add(-5 * time.Second))}
			cfg := Config{MaxAge: time.Minute, Bindings: []Binding{{ProviderID: "u", ConsoleID: "console", ClientID: "nyc", LocationID: "nyc", Medium: "wifi", SecretFile: "fixed-secret"}}}
			r.fail = fail == "validate"
			f.fail = fail == "firewall"
			a := Applier{Config: cfg, Verifier: verifier{got: []domain.SourceCandidate{c}}, Operations: o}
			_, e := a.Apply(context.Background(), []domain.SourceCandidate{c}, false)
			clients, _ := os.ReadFile(o.clientsPath)
			state, _ := os.ReadFile(o.statePath)
			if fail != "none" {
				if e == nil || string(clients) != "previous-clients" || string(state) != `{"Candidates":[]}` || !reflect.DeepEqual(f.rule, oldRule) {
					t.Fatalf("failed transaction left changes err %v clients %s state %s rule %+v", e, clients, state, f.rule)
				}
				if strings.Contains(e.Error(), "SENTINEL") {
					t.Fatal("secret leaked")
				}
			} else {
				if e != nil || !strings.Contains(string(clients), "8.8.8.8/32") || !strings.Contains(string(state), "8.8.8.8/32") || r.validate != 1 || r.activate != 1 || r.health != 2 || len(f.patches) != 1 {
					t.Fatalf("incomplete success %v %+v %+v", e, r, f)
				}
				if f.rule.Name != oldRule.Name || f.rule.Network != oldRule.Network || !reflect.DeepEqual(f.rule.Allowed, oldRule.Allowed) || !reflect.DeepEqual(f.rule.TargetTags, oldRule.TargetTags) {
					t.Fatal("firewall target/ports changed")
				}
			}
		})
	}
}
func TestFirewallScopeChangesAndTimeoutNeverCommit(t *testing.T) {
	o, _, f := fixtureOps(t)
	f.rule.TargetTags = []string{"other-node"}
	if _, e := o.Snapshot(context.Background()); e == nil {
		t.Fatal("wrong node accepted")
	}
	f.rule.TargetTags = []string{"radius-primary"}
	f.never = true
	if e := o.Converge(context.Background(), Plan{SourceRanges: []string{"8.8.8.8/32"}}); e == nil {
		t.Fatal("unconverged patch succeeded")
	}
	b, _ := os.ReadFile(o.statePath)
	if string(b) != `{"Candidates":[]}` {
		t.Fatal("convergence advanced freshness")
	}
}
func TestFirewallRejectsBroadExistingSourceBeforeMutation(t *testing.T) {
	o, _, f := fixtureOps(t)
	f.rule.SourceRanges = []string{"0.0.0.0/0"}
	if _, e := o.Snapshot(context.Background()); e == nil {
		t.Fatal("unsafe existing firewall scope accepted")
	}
	if len(f.patches) != 0 {
		t.Fatal("unsafe firewall mutated")
	}
}
func TestExactReadOnlyReconciliationAndConfigBinding(t *testing.T) {
	o, _, f := fixtureOps(t)
	now := time.Now()
	candidate := domain.SourceCandidate{ProviderID: "u", SiteID: "console", CIDRs: []string{"8.8.8.8/32"}, ObservedAt: domain.Unix(now)}
	cfg := Config{MaxAge: time.Minute, Bindings: []Binding{{ProviderID: "u", ProviderOrigin: "https://controller.invalid/v1", ConsoleID: "console", ClientID: "nyc", LocationID: "nyc", Medium: "wifi", SecretFile: "fixed-secret", StaticCIDRs: []string{"10.0.0.0/24"}}}}
	a := Applier{Config: cfg, Verifier: verifier{got: []domain.SourceCandidate{candidate}}, Operations: o, Now: func() time.Time { return now }}
	if _, e := a.Apply(context.Background(), []domain.SourceCandidate{candidate}, false); e != nil {
		t.Fatal(e)
	}
	before, _ := os.ReadFile(o.statePath)
	var state State
	if e := json.Unmarshal(before, &state); e != nil {
		t.Fatal(e)
	}
	patches := len(f.patches)
	evidence, e := a.ReconcileApplied(context.Background(), []domain.SourceCandidate{candidate})
	if e != nil || evidence.Node != "radius-primary" || len(evidence.ClientsSHA256) != 64 || len(f.patches) != patches {
		t.Fatalf("bad read-only reconciliation %+v %v", evidence, e)
	}
	after, _ := os.ReadFile(o.statePath)
	if !bytes.Equal(before, after) {
		t.Fatal("reconciliation freshened state")
	}
	cfg.Bindings[0].ProviderOrigin = "https://other.invalid/v1"
	if Allowed(cfg, state, "nyc", "8.8.8.8", now) || !Allowed(cfg, state, "nyc", "10.0.0.5", now) {
		t.Fatal("config change retained dynamic trust or disabled static fallback")
	}
	a.Config = cfg
	if _, e = a.ReconcileApplied(context.Background(), []domain.SourceCandidate{candidate}); e == nil {
		t.Fatal("reconciled old state after source config change")
	}
	serialized, _ := json.Marshal(state)
	if strings.Contains(string(serialized), strings.Repeat("a", 32)) || strings.Contains(string(serialized), "fixed-secret") {
		t.Fatal("state leaked secret/reference")
	}
	info, _ := os.Stat(o.statePath)
	if info.Mode().Perm() != 0644 {
		t.Fatal("applied state not readable by daemon")
	}
}
