package app

import (
	"context"
	"errors"
	"reflect"

	"github.com/CampusTech/cloud-8021x/internal/adapters/fleet"
	"github.com/CampusTech/cloud-8021x/internal/migration"
	"github.com/CampusTech/cloud-8021x/internal/storage/postgres"
)

type legacyGuardStore interface {
	LegacyCollectionGuard(context.Context, string) (postgres.LegacyCollectionGuard, error)
	ResolveLegacyCollection(context.Context, string, fleet.LegacyRecoveryEvidence) error
}
type legacyCommandReader interface {
	RecoverLegacyCommand(context.Context, string, string, migration.LegacyCertificateHost, migration.LegacyCommand, string) (fleet.LegacyRecoveryEvidence, error)
}
type legacyGuardGate interface {
	With(context.Context, string, func(context.Context) error) error
}

func resolveLegacyGuard(ctx context.Context, s legacyGuardStore, c legacyCommandReader, g legacyGuardGate, id, operation, hint string) error {
	guard, e := s.LegacyCollectionGuard(ctx, id)
	if e != nil {
		return e
	}
	if guard.State == "resolved" {
		return nil
	}
	proof, e := c.RecoverLegacyCommand(ctx, guard.Source, guard.HostUUID, guard.Host, guard.Command, hint)
	if e != nil {
		return e
	}
	return g.With(ctx, operation, func(ctx context.Context) error {
		original, e := s.LegacyCollectionGuard(ctx, id)
		if e != nil {
			return e
		}
		if !reflect.DeepEqual(original, guard) {
			return errors.New("original collection guard changed before resolution")
		}
		return s.ResolveLegacyCollection(ctx, id, proof)
	})
}
