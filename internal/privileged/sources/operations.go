package sources

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/network"
)

const ClientsFile = "/etc/cloud-8021x/sources/clients.conf"
const StateFile = "/var/lib/cloud-8021x-source-state/state.json"
const ProofDirectory = "/var/lib/cloud-8021x-source-proof"

// Radius.Activate must perform a fixed root-started restart, not a reload as
// freerad: the private include is intentionally unreadable after privilege drop.
// Task8 owns actual commands; Task9 coordinates restarts across the HA pair.
type Radius interface {
	Validate(context.Context) error
	Activate(context.Context) error
	Healthy(context.Context) error
}
type FirewallTarget struct{ Project, Node, Network string }
type FirewallRule struct {
	SourceRanges                                             []string
	Disabled                                                 bool
	Name, Network, Direction                                 string
	TargetTags                                               []string
	Allowed                                                  []Port
	SourceTags, SourceServiceAccounts, TargetServiceAccounts []string
	Denied                                                   []Port
}
type Port struct {
	Protocol string
	Ports    []string
}

// Firewall methods operate on an installation-pinned target. Patch has no fields
// for ports, network, direction, tags, rule creation or deletion.
type Firewall interface {
	Read(context.Context) (FirewallRule, error)
	Patch(context.Context, FirewallState) error
}
type SecretReader interface{ ReadSecret(string) ([]byte, error) }
type FileOperations struct {
	Radius                 Radius
	Firewall               Firewall
	Target                 FirewallTarget
	Secrets                SecretReader
	clientsPath, statePath string
	proofPath              string
	stagedProof            string
	clientsChanged         bool
	poll                   time.Duration
}

func NewFileOperations(r Radius, f Firewall, target FirewallTarget, secrets SecretReader) (*FileOperations, error) {
	if r == nil || f == nil || secrets == nil || !regexp.MustCompile(`^[a-z][a-z0-9-]{4,62}$`).MatchString(target.Project) || (target.Node != "radius-primary" && target.Node != "radius-secondary") || target.Network == "" {
		return nil, errors.New("invalid fixed source operation dependencies")
	}
	return &FileOperations{Radius: r, Firewall: f, Target: target, Secrets: secrets, clientsPath: ClientsFile, statePath: StateFile, proofPath: ProofDirectory, poll: time.Second}, nil
}
func (o *FileOperations) check(r FirewallRule) error {
	if !r.Disabled && len(r.SourceRanges) == 0 {
		return errors.New("enabled firewall must have explicit bounded source ranges")
	}
	if len(r.SourceRanges) > 2048 {
		return errors.New("firewall source ranges exceed bound")
	}
	seen := map[string]bool{}
	for _, raw := range r.SourceRanges {
		p, e := netip.ParsePrefix(raw)
		if e != nil || p.Bits() != 32 || raw != p.String() || seen[raw] || (!network.PublicIPv4(p.Addr()) && (!r.Disabled || raw != "192.0.2.1/32")) {
			return errors.New("unsafe existing firewall source ranges")
		}
		seen[raw] = true
	}
	ports := []Port{{Protocol: "udp", Ports: []string{"1812", "1813"}}}
	if r.Name != "allow-"+o.Target.Node+"-discovered" || r.Network != o.Target.Network || r.Direction != "INGRESS" || !reflect.DeepEqual(r.TargetTags, []string{o.Target.Node}) || !reflect.DeepEqual(r.Allowed, ports) || len(r.SourceTags) > 0 || len(r.SourceServiceAccounts) > 0 || len(r.TargetServiceAccounts) > 0 || len(r.Denied) > 0 {
		return errors.New("fixed node firewall identity or allowed ports changed")
	}
	return nil
}
func readOptional(path string, public bool) ([]byte, bool, error) {
	var b []byte
	var e error
	if public {
		b, e = network.ReadPublished(path, os.Geteuid())
	} else {
		b, e = network.ReadPrivate(path, os.Geteuid())
	}
	if errors.Is(e, os.ErrNotExist) {
		return nil, false, nil
	}
	return b, e == nil, e
}
func (o *FileOperations) Snapshot(ctx context.Context) (Backup, error) {
	r, e := o.Firewall.Read(ctx)
	if e != nil {
		return Backup{}, errors.New("firewall read failed")
	}
	if e = o.check(r); e != nil {
		return Backup{}, e
	}
	b := Backup{Firewall: FirewallState{SourceRanges: append([]string(nil), r.SourceRanges...), Disabled: r.Disabled}}
	b.Clients, b.ClientsExist, e = readOptional(o.clientsPath, false)
	if e != nil {
		return Backup{}, e
	}
	b.State, b.StateExist, e = readOptional(o.statePath, true)
	if e != nil {
		return Backup{}, e
	}
	b.Proof, b.ProofExist, e = readOptional(filepath.Join(o.proofPath, "current"), true)
	if e == nil && b.ProofExist && !proofHash.Match(b.Proof) {
		return Backup{}, errors.New("invalid existing source proof pointer")
	}
	return b, e
}
func (o *FileOperations) render(p Plan) ([]byte, error) {
	var text strings.Builder
	safe := regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]{0,127}$`)
	for _, c := range p.Clients {
		if !safe.MatchString(c.ClientID) || !safe.MatchString(c.LocationID) || (c.Medium != "wifi" && c.Medium != "wired") {
			return nil, errors.New("invalid configured client context")
		}
		secret, e := o.Secrets.ReadSecret(c.SecretFile)
		if e != nil {
			return nil, errors.New("source client secret unavailable")
		}
		value := strings.TrimSpace(string(secret))
		if !regexp.MustCompile(`^[A-Za-z0-9]{32,128}$`).MatchString(value) {
			return nil, errors.New("source client secret is invalid")
		}
		for n, cidr := range c.CIDRs {
			if c.ObservedAt <= 0 || c.MaxAgeSeconds < 1 || c.MaxAgeSeconds > 3600 || !proofHash.MatchString(c.ConfigSHA256) {
				return nil, errors.New("dynamic source has no authenticated observation/configuration")
			}
			_, _ = fmt.Fprintf(&text, "client discovered-%s-%d {\n ipaddr = %s\n secret = %s\n shortname = %s\n nastype = other\n c8021x_source_kind = dynamic\n c8021x_max_age = %d\n c8021x_config = %s\n c8021x_client_hash = %s\n}\n", c.ClientID, n, cidr, value, c.ClientID, c.MaxAgeSeconds, c.ConfigSHA256, clientHash(c.ClientID))
		}
	}
	return []byte(text.String()), nil
}
func (o *FileOperations) Install(ctx context.Context, p Plan) error {
	o.stagedProof = ""
	content, e := o.render(p)
	if e != nil {
		return e
	}
	if e = ctx.Err(); e != nil {
		return e
	}
	old, exists, e := readOptional(o.clientsPath, false)
	if e != nil {
		return e
	}
	o.clientsChanged = !exists || !bytes.Equal(old, content)
	o.stagedProof, e = o.stageProof(p)
	if e != nil {
		return e
	}
	if !o.clientsChanged {
		return nil
	}
	return network.WritePrivate(o.clientsPath, content)
}
func (o *FileOperations) Validate(ctx context.Context) error {
	if e := o.Radius.Validate(ctx); e != nil {
		return errors.New("FreeRADIUS configuration validation failed")
	}
	return nil
}
func (o *FileOperations) Activate(ctx context.Context) error {
	if o.clientsChanged {
		if e := o.Radius.Activate(ctx); e != nil {
			return errors.New("FreeRADIUS activation failed")
		}
	}
	if e := o.Radius.Healthy(ctx); e != nil {
		return errors.New("FreeRADIUS did not converge")
	}
	return nil
}
func sameFirewall(r FirewallRule, s FirewallState) bool {
	a, b := append([]string(nil), r.SourceRanges...), append([]string(nil), s.SourceRanges...)
	slices.Sort(a)
	slices.Sort(b)
	return r.Disabled == s.Disabled && slices.Equal(a, b)
}
func (o *FileOperations) converge(ctx context.Context, want FirewallState) error {
	current, e := o.Firewall.Read(ctx)
	if e != nil {
		return errors.New("firewall read failed")
	}
	if e = o.check(current); e != nil {
		return e
	}
	if sameFirewall(current, want) {
		return nil
	}
	if e = o.Firewall.Patch(ctx, want); e != nil {
		return errors.New("firewall patch uncertain")
	}
	for range 20 {
		current, e = o.Firewall.Read(ctx)
		if e != nil {
			return errors.New("firewall convergence read failed")
		}
		if e = o.check(current); e != nil {
			return e
		}
		if sameFirewall(current, want) {
			return nil
		}
		timer := time.NewTimer(o.poll)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
	return errors.New("firewall did not converge")
}
func (o *FileOperations) Converge(ctx context.Context, p Plan) error {
	ranges := p.SourceRanges
	if len(ranges) == 0 {
		ranges = []string{"192.0.2.1/32"}
	}
	if e := o.converge(ctx, FirewallState{SourceRanges: ranges, Disabled: p.Disabled}); e != nil {
		return e
	}
	if e := o.Radius.Healthy(ctx); e != nil {
		return errors.New("FreeRADIUS health lost during firewall convergence")
	}
	return nil
}
func (o *FileOperations) Commit(ctx context.Context, s State) error {
	if e := ctx.Err(); e != nil {
		return e
	}
	b, e := StateBytes(s)
	if e != nil {
		return e
	}
	if !proofHash.MatchString(o.stagedProof) {
		return errors.New("source proof not staged")
	}
	if e = network.WritePublished(o.statePath, b); e != nil {
		return e
	}
	// Publish trust last. Failed validation, activation or convergence cannot freshen it.
	return network.WritePublished(filepath.Join(o.proofPath, "current"), []byte(o.stagedProof))
}
func (o *FileOperations) Rollback(ctx context.Context, b Backup) error {
	var es []error
	restore := func(path string, data []byte, existed bool) error {
		if existed {
			return network.WritePrivate(path, data)
		}
		return network.RemovePrivate(path)
	}
	current, exists, err := readOptional(o.clientsPath, false)
	if err != nil {
		es = append(es, err)
	}
	o.clientsChanged = exists != b.ClientsExist || !bytes.Equal(current, b.Clients)
	es = append(es, restore(o.clientsPath, b.Clients, b.ClientsExist))
	if errors.Join(es...) == nil {
		if err := o.Validate(ctx); err != nil {
			es = append(es, err)
		} else {
			es = append(es, o.Activate(ctx))
		}
	}
	es = append(es, o.converge(ctx, b.Firewall))
	if errors.Join(es...) != nil {
		return errors.New("source rollback did not converge")
	}
	if b.StateExist {
		err = network.WritePublished(o.statePath, b.State)
	} else {
		err = network.RemovePublished(o.statePath)
	}
	if err != nil {
		return err
	}
	if b.ProofExist {
		return network.WritePublished(filepath.Join(o.proofPath, "current"), b.Proof)
	}
	return network.RemovePublished(filepath.Join(o.proofPath, "current"))
}
