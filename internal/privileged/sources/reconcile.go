package sources

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"

	"github.com/CampusTech/cloud-8021x/internal/domain"
)

// ReconciliationEvidence contains hashes and fixed resource identity only. It
// cannot carry resolved RADIUS or vendor credentials. Task9 persists this using
// postgres.ReconcileSuccess for the exact work ID and generation; no resend.
type ReconciliationEvidence struct {
	Node, Network, ConfigSHA256, CandidateSHA256, ClientsSHA256, StateSHA256 string
	ControllerObservedAt                                                     map[string]domain.Timestamp
}
type AppliedVerifier interface {
	VerifyApplied(context.Context, Plan, State) (ReconciliationEvidence, error)
}

func (a *Applier) ReconcileApplied(ctx context.Context, candidates []domain.SourceCandidate) (ReconciliationEvidence, error) {
	if e := a.Config.Validate(); e != nil {
		return ReconciliationEvidence{}, e
	}
	if a.Verifier == nil {
		return ReconciliationEvidence{}, errors.New("authenticated source verifier unavailable")
	}
	check, ok := a.Operations.(AppliedVerifier)
	if !ok {
		return ReconciliationEvidence{}, errors.New("applied source reconciliation unavailable")
	}
	proposed, e := checkedCandidates(candidates, a.Config, nowTime(a.Now), true)
	if e != nil {
		return ReconciliationEvidence{}, e
	}
	rows, e := a.Verifier.Verify(ctx, a.Config.Bindings)
	if e != nil {
		return ReconciliationEvidence{}, errors.New("authenticated reconciliation verification failed")
	}
	trusted, e := canonical(rows, a.Config, nowTime(a.Now))
	if e != nil {
		return ReconciliationEvidence{}, e
	}
	for k, v := range proposed {
		if !reflect.DeepEqual(v.CIDRs, trusted[k].CIDRs) {
			return ReconciliationEvidence{}, errors.New("current pinned controller disagrees with attempted candidate")
		}
	}
	plan, e := makePlan(a.Config, proposed)
	if e != nil {
		return ReconciliationEvidence{}, e
	}
	state := State{ConfigSHA256: a.Config.Identity()}
	for _, b := range a.Config.Bindings {
		if b.ConsoleID != "" {
			state.Candidates = append(state.Candidates, proposed[key(b.ProviderID, b.ConsoleID)])
		}
	}
	evidence, e := check.VerifyApplied(ctx, plan, state)
	if e != nil {
		return ReconciliationEvidence{}, e
	}
	data, e := json.Marshal(candidates)
	if e != nil {
		return ReconciliationEvidence{}, e
	}
	hash := sha256.Sum256(data)
	evidence.CandidateSHA256 = hex.EncodeToString(hash[:])
	evidence.ConfigSHA256 = a.Config.Identity()
	evidence.ControllerObservedAt = map[string]domain.Timestamp{}
	for _, v := range trusted {
		evidence.ControllerObservedAt[v.ProviderID+"/"+v.SiteID] = v.ObservedAt
	}
	return evidence, nil
}

// VerifyApplied is read-only. It requires byte-exact rendered clients, exact
// original applied state, exact fixed firewall ranges/identity and live service
// health. Expired original timestamps stay expired after reconciliation.
func (o *FileOperations) VerifyApplied(ctx context.Context, p Plan, s State) (ReconciliationEvidence, error) {
	snapshot, e := o.Snapshot(ctx)
	if e != nil {
		return ReconciliationEvidence{}, e
	}
	clients, e := o.render(p)
	if e != nil {
		return ReconciliationEvidence{}, e
	}
	state, e := StateBytes(s)
	if e != nil {
		return ReconciliationEvidence{}, e
	}
	ranges := p.SourceRanges
	if len(ranges) == 0 {
		ranges = []string{"192.0.2.1/32"}
	}
	actual := FirewallRule{SourceRanges: snapshot.Firewall.SourceRanges, Disabled: snapshot.Firewall.Disabled}
	if !snapshot.ClientsExist || !snapshot.StateExist || !bytes.Equal(clients, snapshot.Clients) || !bytes.Equal(state, snapshot.State) || !sameFirewall(actual, FirewallState{SourceRanges: ranges, Disabled: p.Disabled}) {
		return ReconciliationEvidence{}, errors.New("actual fixed source state does not match attempted candidate")
	}
	if e = o.Radius.Healthy(ctx); e != nil {
		return ReconciliationEvidence{}, errors.New("source reconciliation service health failed")
	}
	ch, sh := sha256.Sum256(clients), sha256.Sum256(state)
	return ReconciliationEvidence{Node: o.Target.Node, Network: o.Target.Network, ClientsSHA256: hex.EncodeToString(ch[:]), StateSHA256: hex.EncodeToString(sh[:])}, nil
}
