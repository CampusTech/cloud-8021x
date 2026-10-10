// Package network supplies callable refresh services for sites sync and schedules.
package network

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"sync"

	"github.com/CampusTech/cloud-8021x/internal/domain"
	metadata "github.com/CampusTech/cloud-8021x/internal/network"
)

type Service struct {
	Key      string
	Registry *metadata.Registry
	Store    *metadata.Store
	Path     string
	Output   io.Writer
	mu       sync.Mutex
}
type Document struct {
	Key       string
	Providers []domain.NetworkSnapshot
}

func (s *Service) Sync(ctx context.Context, dry bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.Registry == nil || s.Store == nil {
		return errors.New("network service is not configured")
	}
	old := Document{}
	if s.Path != "" {
		if b, e := metadata.ReadPrivate(s.Path, os.Geteuid()); e == nil {
			if e = domain.DecodeJSONStrict(b, &old); e != nil {
				return errors.New("invalid metadata document")
			}
			if old.Key != s.Key {
				old = Document{}
			}
			for _, p := range old.Providers {
				if e = metadata.Validate(p); e != nil {
					return e
				}
			}
		}
	}
	next := Document{Key: s.Key}
	var failures []error
	for _, r := range s.Registry.Entries {
		b, e := r.Inventory.Fetch(ctx, r.Scope)
		if e != nil {
			failures = append(failures, fmt.Errorf("provider %s refresh failed", r.ID))
			b = domain.NetworkSnapshot{ProviderID: r.ID, Scope: r.Scope}
			for _, id := range r.Scope.IDs {
				b.Scopes = append(b.Scopes, domain.NetworkScopeResult{ScopeID: id, Status: domain.CapabilityFailed})
			}
		}
		if e = metadata.Validate(b); e != nil {
			return e
		}
		if b.ProviderID != r.ID || !reflect.DeepEqual(b.Scope, r.Scope) {
			return errors.New("provider identity mismatch")
		}
		for _, result := range b.Scopes {
			if result.Status == domain.CapabilityFailed || result.VLANStatus == domain.CapabilityFailed {
				failures = append(failures, fmt.Errorf("provider %s scope %s failed", r.ID, result.ScopeID))
			}
		}
		for _, prev := range old.Providers {
			if prev.ProviderID == r.ID {
				b = metadata.Merge(prev, b)
				break
			}
		}
		next.Providers = append(next.Providers, b)
	}
	if e := ctx.Err(); e != nil {
		return e
	}
	if dry {
		if s.Output != nil {
			_, e := fmt.Fprintf(s.Output, "Checked %d network providers; no metadata or cache written.\n", len(next.Providers))
			if e != nil {
				return e
			}
		}
		return errors.Join(failures...)
	}
	data, e := json.Marshal(next)
	if e != nil {
		return e
	}
	if s.Path != "" {
		if e = metadata.WritePrivate(s.Path, data); e != nil {
			return e
		}
	}
	if e = s.Store.Replace(next.Providers); e != nil {
		return e
	}
	return errors.Join(failures...)
}

type Discovery struct {
	Provider domain.SourceDiscoveryProvider
	Scope    domain.InventoryScope
}

// Discover does no privileged work and writes candidates only when every pinned
// source fetch succeeds. Root independently authenticates this evidence again.
func Discover(ctx context.Context, providers []Discovery, path string, dry bool) ([]domain.SourceCandidate, error) {
	all := []domain.SourceCandidate{}
	for _, p := range providers {
		if p.Provider == nil {
			return nil, errors.New("source discovery unsupported")
		}
		v, e := p.Provider.DiscoverSources(ctx, p.Scope)
		if e != nil {
			return nil, e
		}
		all = append(all, v...)
	}
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	if !dry {
		b, e := json.Marshal(all)
		if e != nil {
			return nil, e
		}
		if e = metadata.WritePrivate(path, b); e != nil {
			return nil, e
		}
	}
	return all, nil
}
