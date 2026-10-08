package app

import (
	"context"
	"errors"
	"testing"

	"github.com/CampusTech/cloud-8021x/internal/adapters/fleet"
	"github.com/CampusTech/cloud-8021x/internal/migration"
	"github.com/CampusTech/cloud-8021x/internal/storage/postgres"
)

type pendingGuardStore struct{ resolved bool }

func (*pendingGuardStore) LegacyCollectionGuard(context.Context, string) (postgres.LegacyCollectionGuard, error) {
	return postgres.LegacyCollectionGuard{State: "quarantine", Source: "https://fixture.invalid", HostUUID: "original-host"}, nil
}
func (s *pendingGuardStore) ResolveLegacyCollection(context.Context, string, fleet.LegacyRecoveryEvidence) error {
	s.resolved = true
	return nil
}

type pendingGuardClient struct{}

func (pendingGuardClient) RecoverLegacyCommand(context.Context, string, string, migration.LegacyCertificateHost, migration.LegacyCommand, string) (fleet.LegacyRecoveryEvidence, error) {
	return fleet.LegacyRecoveryEvidence{}, errors.New("original command still pending")
}

type pendingGuardGate struct{ entered bool }

func (g *pendingGuardGate) With(ctx context.Context, _ string, f func(context.Context) error) error {
	g.entered = true
	return f(ctx)
}
func TestPendingLegacyPollDoesNotQuarantineRootMaintenance(t *testing.T) {
	s := new(pendingGuardStore)
	g := new(pendingGuardGate)
	if e := resolveLegacyGuard(context.Background(), s, pendingGuardClient{}, g, "guard", "operation", ""); e == nil || g.entered || s.resolved {
		t.Fatal("read-only pending result entered mutation gate", e)
	}
}
