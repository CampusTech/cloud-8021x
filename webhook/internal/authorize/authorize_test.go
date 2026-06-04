package authorize

import (
	"context"
	"errors"
	"testing"

	"github.com/CampusTech/cloud-8021x/webhook/internal/fleet"
)

type fakeLookup struct {
	host *fleet.Host
	err  error
}

func (f fakeLookup) LookupHostBySerial(_ context.Context, _ string) (*fleet.Host, error) {
	return f.host, f.err
}

func TestDecide(t *testing.T) {
	enrolled := &fleet.Host{Enrolled: true, Labels: []string{"All Hosts", "test-pilots"}}
	cases := []struct {
		name      string
		serial    string
		allowLbl  string
		lookup    fakeLookup
		wantAllow bool
	}{
		{"empty serial denied", "", "", fakeLookup{host: enrolled}, false},
		{"enrolled no-label-gate allowed", "S", "", fakeLookup{host: enrolled}, true},
		{"not enrolled denied", "S", "", fakeLookup{host: nil}, false},
		{"fleet error denied (fail-closed)", "S", "", fakeLookup{err: errors.New("boom")}, false},
		{"label gate satisfied", "S", "test-pilots", fakeLookup{host: enrolled}, true},
		{"label gate missing label denied", "S", "prod-only", fakeLookup{host: enrolled}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := New(tc.lookup, tc.allowLbl)
			got := a.Decide(context.Background(), tc.serial)
			if got != tc.wantAllow {
				t.Fatalf("Decide=%v want %v", got, tc.wantAllow)
			}
		})
	}
}
