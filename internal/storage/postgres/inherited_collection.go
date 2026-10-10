package postgres

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/migration"
	"github.com/jackc/pgx/v5"
)

// InheritedCollection reads authenticated source observations. Runtime cannot
// insert or update this cache, and these records never become delivery work.
func (s *Store) InheritedCollection(ctx context.Context, scope string) ([]byte, error) {
	if !transitionDigest.MatchString(scope) {
		return nil, errors.New("invalid inherited collection scope")
	}
	ctx, cancel := s.bounded(ctx)
	defer cancel()
	var raw []byte
	err := s.pool.QueryRow(ctx, `SELECT document FROM ledger.inherited_certificates WHERE scope=$1`, scope).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return raw, safeError(err)
}

// The protected transition lock serializes peer imports. Select the latest
// original observation within a binding and its maximum original attempt.
// Across bindings, the latest original activity supersedes the old binding;
// exact runtime validation leaves superseded binding data unusable. Equal-time
// conflicting authority fails closed.
func importInheritedCollections(ctx context.Context, tx pgx.Tx, certificates migration.LegacyCertificateState) error {
	for uuid, host := range certificates.Hosts {
		var id uint64
		if json.Unmarshal(host.Binding[0], &id) != nil {
			return errors.New("invalid inherited host ID")
		}
		scope := migration.LegacyCollectionScope(certificates.Source, id, uuid)
		next := migration.LegacyCertificateState{Version: 1, Source: certificates.Source, Trust: certificates.Trust, Hosts: map[string]migration.LegacyCertificateHost{uuid: host}, Commands: []migration.LegacyCommand{}}
		var priorRaw []byte
		err := tx.QueryRow(ctx, `SELECT document FROM ledger.inherited_certificates WHERE scope=$1 FOR UPDATE`, scope).Scan(&priorRaw)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return safeError(err)
		}
		if err == nil {
			prior, e := migration.DecodeCertificates(priorRaw)
			if e != nil || len(prior.Hosts) != 1 {
				return errors.New("invalid retained inherited observation")
			}
			old, ok := prior.Hosts[uuid]
			if !ok {
				return errors.New("inherited host scope changed")
			}
			originalAt := func(h migration.LegacyCertificateHost) time.Time {
				if h.Observation == nil {
					return time.Time{}
				}
				at, _ := migration.ReceiptTime([]byte(h.Observation.ObservedAt))
				return at
			}
			oldAt, nextAt := originalAt(old), originalAt(host)
			oldBinding, _ := json.Marshal([]any{prior.Source, prior.Trust, old.Platform, old.Binding, old.PollingExempt})
			nextBinding, _ := json.Marshal([]any{next.Source, next.Trust, host.Platform, host.Binding, host.PollingExempt})
			sameBinding := bytes.Equal(oldBinding, nextBinding)
			if sameBinding && oldAt.Equal(nextAt) {
				a, b := old, host
				a.LastAttempt, b.LastAttempt = "0", "0"
				oldContent, _ := json.Marshal(a)
				nextContent, _ := json.Marshal(b)
				if !bytes.Equal(oldContent, nextContent) {
					return errors.New("peer inherited observation conflicts at original timestamp")
				}
			}
			oldAttempt, _ := migration.ReceiptTime([]byte(old.LastAttempt))
			nextAttempt, _ := migration.ReceiptTime([]byte(host.LastAttempt))
			if !sameBinding {
				if oldAttempt.After(oldAt) {
					oldAt = oldAttempt
				}
				if nextAttempt.After(nextAt) {
					nextAt = nextAttempt
				}
				if oldAt.Equal(nextAt) {
					return errors.New("peer inherited binding conflicts at original activity timestamp")
				}
			}
			if oldAt.After(nextAt) {
				next = prior
				host = old
			}
			if sameBinding {
				if oldAttempt.After(nextAttempt) {
					host.LastAttempt = old.LastAttempt
				} else {
					host.LastAttempt = certificates.Hosts[uuid].LastAttempt
				}
				next.Hosts[uuid] = host
			}
		}
		raw, err := json.Marshal(next)
		if err != nil {
			return err
		}
		if _, err = tx.Exec(ctx, `INSERT INTO ledger.inherited_certificates(scope,document) VALUES($1,$2) ON CONFLICT(scope) DO UPDATE SET document=EXCLUDED.document`, scope, raw); err != nil {
			return safeError(err)
		}
	}
	return nil
}
