package network

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"sync"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/domain"
)

type CachedProvider struct {
	Provider  domain.NetworkInventoryProvider
	Key, Path string
	MaxAge    time.Duration
	Now       func() time.Time
	mu        sync.Mutex
}
type cache struct {
	Key   string
	Batch domain.NetworkSnapshot
}

func (c *CachedProvider) Fetch(ctx context.Context, scope domain.InventoryScope) (domain.NetworkSnapshot, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if e := ctx.Err(); e != nil {
		return domain.NetworkSnapshot{}, e
	}
	now := time.Now()
	if c.Now != nil {
		now = c.Now()
	}
	if c.Provider == nil || c.Key == "" || c.MaxAge <= 0 {
		return domain.NetworkSnapshot{}, errors.New("invalid network cache")
	}
	if b, e := ReadPrivate(c.Path, os.Geteuid()); e == nil {
		var v cache
		if domain.DecodeJSONStrict(b, &v) == nil && v.Key == c.Key && reflect.DeepEqual(scope, v.Batch.Scope) && Validate(v.Batch) == nil {
			valid := true
			for _, s := range v.Batch.Scopes {
				if s.Status != domain.CapabilityAvailable || s.VLANStatus == domain.CapabilityFailed || !domain.Fresh(s.ObservedAt, now, c.MaxAge) {
					valid = false
				}
			}
			if valid {
				return v.Batch, nil
			}
		}
	}
	b, e := c.Provider.Fetch(ctx, scope)
	if e != nil {
		return b, e
	}
	if !reflect.DeepEqual(b.Scope, scope) {
		return b, errors.New("network cache scope mismatch")
	}
	if e = Validate(b); e != nil {
		return b, e
	}
	for _, s := range b.Scopes {
		if s.Status != domain.CapabilityAvailable || s.VLANStatus == domain.CapabilityFailed {
			return b, nil
		}
	}
	data, e := json.Marshal(cache{c.Key, b})
	if e != nil {
		return b, e
	}
	if e = ctx.Err(); e != nil {
		return b, e
	}
	if e = WritePrivate(c.Path, data); e != nil {
		return b, errors.New("network cache publication failed")
	}
	return b, nil
}

// Merge retains unsuccessful scopes and their original timestamps, dropping scopes
// no longer configured. It never broadens scope based on controller output.
func Merge(old, next domain.NetworkSnapshot) domain.NetworkSnapshot {
	out := next
	out.Scopes = nil
	out.Sites = nil
	out.Authenticators = nil
	out.VLANs = nil
	for _, r := range next.Scopes {
		src := next
		if r.Status != domain.CapabilityAvailable && old.ProviderID == next.ProviderID {
			for _, o := range old.Scopes {
				if o.ScopeID == r.ScopeID && o.Status == domain.CapabilityAvailable {
					r = o
					src = old
					break
				}
			}
		}
		vlanSource := src
		if src.ProviderID == next.ProviderID && (r.VLANStatus == domain.CapabilityFailed || r.VLANStatus == domain.CapabilityUnsupported) {
			for _, previous := range old.Scopes {
				if old.ProviderID == next.ProviderID && previous.ScopeID == r.ScopeID && (previous.VLANStatus == domain.CapabilityAvailable || previous.VLANStatus == "") && previous.Status == domain.CapabilityAvailable {
					vlanSource = old
					r.VLANStatus = previous.VLANStatus
					r.VLANObservedAt = previous.VLANObservedAt
					if r.VLANObservedAt == 0 {
						r.VLANObservedAt = previous.ObservedAt
					}
					break
				}
			}
		}
		out.Scopes = append(out.Scopes, r)
		if r.Status != domain.CapabilityAvailable {
			continue
		}
		for _, s := range src.Sites {
			if s.ID == r.ScopeID {
				out.Sites = append(out.Sites, s)
			}
		}
		for _, a := range src.Authenticators {
			if a.SiteID == r.ScopeID {
				out.Authenticators = append(out.Authenticators, a)
			}
		}
		for _, v := range vlanSource.VLANs {
			if v.SiteID == r.ScopeID {
				out.VLANs = append(out.VLANs, v)
			}
		}
	}
	return out
}
