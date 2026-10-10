package policy

import (
	"encoding/json"
	"sync/atomic"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/domain"
	"github.com/CampusTech/cloud-8021x/internal/privileged/sources"
)

// ClientResolver accepts only native authenticated client/transport context.
type ClientResolver interface {
	AuthenticatedClient(clientID, source string) (domain.TrustedNetworkContext, error)
}

// SourceTrust has no filesystem or controller I/O in the authorization path.
// Refresh must be scheduled separately. Failed refresh removes dynamic grants,
// while static configured ranges remain available.
type SourceTrust struct {
	config sources.Config
	state  atomic.Pointer[sources.State]
	clock  func() time.Time
}

func NewSourceTrust(cfg sources.Config) (*SourceTrust, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	// Do not retain caller-mutable configuration slices.
	raw, _ := json.Marshal(cfg)
	var copy sources.Config
	if err := json.Unmarshal(raw, &copy); err != nil {
		return nil, err
	}
	return &SourceTrust{config: copy, clock: time.Now}, nil
}
func (t *SourceTrust) Refresh() error {
	state, err := sources.ReadState()
	if err != nil {
		t.state.Store(nil)
		return err
	}
	t.state.Store(&state)
	return nil
}
func (t *SourceTrust) AuthenticatedClient(id, source string) (domain.TrustedNetworkContext, error) {
	state := sources.State{}
	if p := t.state.Load(); p != nil {
		state = *p
	}
	return sources.AuthenticatedClient(t.config, state, id, source, t.clock())
}
