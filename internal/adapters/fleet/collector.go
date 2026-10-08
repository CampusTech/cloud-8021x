package fleet

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/domain"
	"github.com/CampusTech/cloud-8021x/internal/inventory"
	"github.com/CampusTech/cloud-8021x/internal/jobs"
	"github.com/CampusTech/cloud-8021x/internal/migration"
)

//go:embed windows_certificates.ps1
var windowsScript string

type CollectionOptions struct {
	Cadence, MaxAge            time.Duration
	SCEPProfiles, ACMEProfiles []string
	BatchBudget                int
}
type Collector struct {
	ReloadTrust func() (*Trust, error)
	Maintainer  *Client
	Repository  inventory.CollectionRepository
	Trust       *Trust
	Options     CollectionOptions
	Owner       string
	Now         func() time.Time
	mu          sync.Mutex
	hosts       map[domain.DeviceID]host
	requests    int
	selected    map[domain.DeviceID]bool
	order       []domain.DeviceID
}

var _ domain.ManagedCertificateProvider = (*Collector)(nil)

func (c *Collector) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

// Prepare intersects two complete authenticated inventories. The observer batch
// does not delegate its global scope to the separately scoped maintainer.
func (c *Collector) Prepare(ctx context.Context, batch domain.DeviceSnapshot) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.ReloadTrust != nil {
		trust, err := c.ReloadTrust()
		if err != nil {
			return err
		}
		c.Trust = trust
	}
	if !batch.Complete || batch.Scope.ProviderID != "fleet" || c.Maintainer == nil || c.Trust == nil {
		return errors.New("invalid Fleet certificate preparation")
	}
	scoped, err := (&Observer{Client: c.Maintainer}).hosts(ctx)
	if err != nil {
		return err
	}
	counts := map[string]int{}
	for _, h := range scoped {
		if h.UUID != "" {
			counts[domain.NormalizeIdentity(h.UUID)]++
		}
	}
	observed := map[domain.DeviceID]domain.Device{}
	for _, d := range batch.Devices {
		observed[d.ID] = d
	}
	eligible := map[domain.DeviceID]host{}
	for _, h := range scoped {
		d, ok := observed[domain.DeviceID("fleet:"+itoa(h.ID))]
		if !ok || !d.Enrolled || h.UUID == "" || counts[domain.NormalizeIdentity(h.UUID)] != 1 {
			continue
		}
		for _, alias := range d.Identities {
			if alias == domain.NormalizeIdentity(h.UUID) {
				eligible[d.ID] = h
				break
			}
		}
	}
	c.hosts = eligible
	c.requests = 0
	return c.prepareSelection(ctx)
}
func installed(h host, uuids []string, verified bool) bool {
	for _, p := range h.MDM.Profiles {
		if p.Operation == "install" && (!verified || p.Status == "verified") {
			for _, uuid := range uuids {
				if p.UUID == uuid {
					return true
				}
			}
		}
	}
	return false
}
func (c *Collector) boundHost(ctx context.Context, id domain.DeviceID) (host, reservation, error) {
	listed, ok := c.hosts[id]
	if !ok {
		return host{}, reservation{}, inventory.ErrIneligible
	}
	var detail struct {
		Host *host `json:"host"`
	}
	if err := c.Maintainer.request(ctx, "GET", "/api/v1/fleet/hosts/"+itoa(listed.ID), nil, &detail); err != nil {
		if errors.Is(err, errNotFound) {
			return host{}, reservation{}, inventory.ErrIneligible
		}
		return host{}, reservation{}, err
	}
	if detail.Host == nil {
		return host{}, reservation{}, errors.New("missing Fleet host detail")
	}
	h := *detail.Host
	if h.ID != listed.ID || h.UUID != listed.UUID || h.Platform != listed.Platform || !h.enrolled() {
		return host{}, reservation{}, inventory.ErrIneligible
	}
	apple := h.Platform == "darwin" || h.Platform == "macos" || h.Platform == "ios" || h.Platform == "ipados"
	if apple && !managedOnlySupported(h.Platform, h.OSVersion) {
		return host{}, reservation{}, inventory.ErrIneligible
	}
	if !apple && h.Platform != "windows" {
		return host{}, reservation{}, inventory.ErrIneligible
	}
	if h.Platform == "windows" && !h.ScriptsEnabled {
		return host{}, reservation{}, inventory.ErrIneligible
	}
	scep := installed(h, c.Options.SCEPProfiles, false)
	if (c.Options.SCEPProfiles != nil && !scep) || (apple && installed(h, c.Options.ACMEProfiles, true) && !scep) {
		return host{}, reservation{}, inventory.ErrIneligible
	}
	enrollment := h.MDMEnrolledAt
	transport := "apple"
	if h.Platform == "windows" {
		enrollment = h.EnrolledAt
		transport = "windows"
	}
	at, err := time.Parse(time.RFC3339Nano, enrollment)
	if err != nil || at.Unix() <= 0 || at.After(c.now()) {
		return host{}, reservation{}, inventory.ErrIneligible
	}
	r := reservation{HostID: h.ID, HostUUID: h.UUID, EnrolledAt: float64(domain.Unix(at)), FleetEnrolledAt: h.EnrolledAt, Transport: transport, ManagedOnly: apple, Trust: c.Trust.digest}
	scriptHash := sha256.Sum256([]byte(windowsScript))
	binding := fmt.Sprintf("%s\x00%d\x00%s\x00%s\x00%s\x00%s\x00%s", c.Maintainer.base, h.ID, h.UUID, enrollment, h.EnrolledAt, c.Trust.digest, transport)
	if transport == "windows" {
		binding += "\x00" + hex.EncodeToString(scriptHash[:])
	}
	key := sha256.Sum256([]byte(binding))
	r.Key = hex.EncodeToString(key[:])
	r.LegacyScope = migration.LegacyCollectionScope(c.Maintainer.base, uint64(h.ID), h.UUID)
	return h, r, nil
}

type collectionReceipt struct {
	Pending     bool                           `json:"pending"`
	ExecutionID string                         `json:"execution_id,omitempty"`
	Observation *domain.CertificateObservation `json:"observation,omitempty"`
}

func receiptJSON(v any) json.RawMessage { data, _ := json.Marshal(v); return data }
func (c *Collector) limits() (time.Duration, time.Duration, int, error) {
	cadence := c.Options.Cadence
	if cadence == 0 {
		cadence = time.Hour
	}
	age := c.Options.MaxAge
	if age == 0 {
		age = 24 * time.Hour
	}
	budget := c.Options.BatchBudget
	if budget == 0 {
		budget = 100
	}
	if cadence < time.Hour || cadence > 30*24*time.Hour || age <= 0 || age > 30*24*time.Hour || budget < 1 || budget > 100 {
		return 0, 0, 0, errors.New("invalid Fleet certificate bounds")
	}
	return cadence, age, budget, nil
}
func (c *Collector) Collect(ctx context.Context, request domain.CertificateCollectionRequest) (domain.CertificateObservation, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	_, binding, err := c.boundHost(ctx, request.DeviceID)
	if err != nil {
		return domain.CertificateObservation{}, err
	}
	cadence, age, budget, err := c.limits()
	if err != nil {
		return domain.CertificateObservation{}, err
	}
	if c.Repository == nil {
		return domain.CertificateObservation{}, errors.New("fleet collection requires durable repository")
	}
	kind := "fleet-cert:" + binding.Key[:48]
	owner := c.Owner
	if owner == "" {
		owner = "fleet-collector"
	}
	// Claim sweeps expired started attempts to quarantine before result recovery.
	// An already reserved pending request may be claimed; handle it below using
	// its durable payload, never the newly generated reservation.
	claim, err := c.Repository.Claim(ctx, kind, owner, time.Minute)
	if err != nil {
		return domain.CertificateObservation{}, err
	}
	works, err := c.Repository.ListCollection(ctx, binding.Key)
	if err != nil {
		return domain.CertificateObservation{}, err
	}
	var best *domain.CertificateObservation
	for _, work := range works {
		var r reservation
		var receipt collectionReceipt
		if json.Unmarshal(work.Payload, &r) != nil || r.Key != binding.Key || r.HostID != binding.HostID || r.HostUUID != binding.HostUUID || r.Trust != binding.Trust || json.Unmarshal(work.Receipt, &receipt) != nil && len(work.Receipt) != 0 {
			return domain.CertificateObservation{}, errors.New("invalid durable Fleet collection state")
		}
		if receipt.Observation != nil {
			ob := receipt.Observation
			if ob.TrustVerified && ob.DeviceID == request.DeviceID && ob.Provenance != "" && domain.Fresh(ob.ObservedAt, c.now(), age) {
				copy := *ob
				copy.Fingerprints = []string{}
				for _, fp := range ob.Fingerprints {
					if ob.ExpiresAt[fp] > domain.Unix(c.now()) {
						copy.Fingerprints = append(copy.Fingerprints, fp)
					}
				}
				if best == nil || copy.ObservedAt > best.ObservedAt {
					best = &copy
				}
			}
			continue
		}
		if work.State == "pending" || work.State == "leased" || work.State == "started" {
			continue
		}
		if work.State == "succeeded" && !receipt.Pending {
			continue
		}
		r.ExecutionID = receipt.ExecutionID
		ob, terminal, e := c.poll(ctx, r, age)
		if e != nil {
			return domain.CertificateObservation{}, e
		}
		if !terminal {
			continue
		}
		next := collectionReceipt{Observation: ob, ExecutionID: r.ExecutionID}
		evidence := map[string]any{"command_uuid": r.UUID, "host_id": r.HostID, "host_uuid": r.HostUUID, "execution_id": r.ExecutionID, "provenance_verified": true}
		if e = c.Repository.RecordCollectionResult(ctx, work.ID, work.Generation, receiptJSON(next), receiptJSON(evidence)); e != nil {
			return domain.CertificateObservation{}, e
		}
		if ob != nil && (best == nil || ob.ObservedAt > best.ObservedAt) {
			best = ob
		}
	}
	if claim != nil && c.selected[request.DeviceID] && c.requests < budget {
		if err = c.submit(ctx, *claim, binding); err != nil {
			return domain.CertificateObservation{}, err
		}
		c.requests++
	} else if claim == nil && c.selected[request.DeviceID] && c.requests < budget && (best == nil || !domain.Fresh(best.ObservedAt, c.now(), cadence)) {
		var nonce [16]byte
		if _, err = rand.Read(nonce[:]); err != nil {
			return domain.CertificateObservation{}, errors.New("collection nonce generation failed")
		}
		nonce[6] = (nonce[6] & 0x0f) | 0x40
		nonce[8] = (nonce[8] & 0x3f) | 0x80
		binding.UUID = fmt.Sprintf("%x-%x-%x-%x-%x", nonce[:4], nonce[4:6], nonce[6:8], nonce[8:10], nonce[10:])
		binding.CreatedAt = float64(domain.Unix(c.now()))
		if binding.Transport == "windows" {
			binding.Script = windowsScript + "\n# Collection nonce: " + binding.UUID + "\n"
		}
		id := "fleet-cert:" + binding.Key + ":" + binding.UUID
		reserved, e := c.Repository.ReserveCollection(ctx, id, kind, binding.Key, receiptJSON(binding), cadence, 2)
		if e != nil {
			return domain.CertificateObservation{}, e
		}
		if reserved {
			claim, e = c.Repository.Claim(ctx, kind, owner, time.Minute)
			if e != nil {
				return domain.CertificateObservation{}, e
			}
			if claim != nil {
				if e = c.submit(ctx, *claim, binding); e != nil {
					return domain.CertificateObservation{}, e
				}
				c.requests++
			}
		}
	}
	if best != nil {
		return *best, nil
	}
	return domain.CertificateObservation{}, inventory.ErrPending
}
func (c *Collector) submit(ctx context.Context, claim jobs.Claim, binding reservation) error {
	var r reservation
	if json.Unmarshal(claim.Payload, &r) != nil || r.Key != binding.Key || r.HostID != binding.HostID || r.HostUUID != binding.HostUUID || r.EnrolledAt != binding.EnrolledAt || r.FleetEnrolledAt != binding.FleetEnrolledAt || r.Transport != binding.Transport || r.Trust != binding.Trust || r.ManagedOnly != binding.ManagedOnly {
		return errors.New("fleet claim binding changed")
	}
	if r.Transport == "windows" && r.Script != windowsScript+"\n# Collection nonce: "+r.UUID+"\n" {
		return errors.New("fleet claim SYSTEM script changed")
	}
	if err := c.Repository.StartAttempt(ctx, claim); err != nil {
		return err
	}
	receipt := collectionReceipt{Pending: true}
	var requestErr error
	if r.Transport == "windows" {
		var response struct {
			HostID      int    `json:"host_id"`
			ExecutionID string `json:"execution_id"`
		}
		requestErr = c.Maintainer.request(ctx, "POST", "/api/v1/fleet/scripts/run", map[string]any{"host_id": r.HostID, "script_contents": r.Script}, &response)
		if requestErr == nil && (response.HostID != r.HostID || response.ExecutionID == "" || len(response.ExecutionID) > 256) {
			requestErr = errors.New("fleet returned unbound script execution")
		}
		if requestErr == nil {
			receipt.ExecutionID = response.ExecutionID
		}
	} else {
		plist := `<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"><plist version="1.0"><dict><key>CommandUUID</key><string>` + r.UUID + `</string><key>Command</key><dict><key>RequestType</key><string>CertificateList</string><key>ManagedOnly</key><true/></dict></dict></plist>`
		var response struct {
			UUID string `json:"command_uuid"`
			Type string `json:"request_type"`
		}
		requestErr = c.Maintainer.request(ctx, "POST", "/api/v1/fleet/commands/run", map[string]any{"command": base64.StdEncoding.EncodeToString([]byte(plist)), "host_uuids": []string{r.HostUUID}}, &response)
		if requestErr == nil && (response.UUID != r.UUID || response.Type != "CertificateList") {
			requestErr = errors.New("fleet returned unbound MDM command")
		}
	}
	outcome := jobs.Succeeded
	if requestErr != nil {
		outcome = jobs.Uncertain
	}
	// A cancelled request still leaves a durable uncertain outcome. Bounded DB
	// cleanup uses its own context, never permission to issue another remote POST.
	finishCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	finishErr := c.Repository.FinishAttempt(finishCtx, claim, outcome, receiptJSON(receipt))
	return errors.Join(requestErr, finishErr)
}
func (c *Collector) poll(ctx context.Context, r reservation, age time.Duration) (*domain.CertificateObservation, bool, error) {
	if r.Transport == "windows" {
		if r.ExecutionID == "" {
			return nil, false, nil
		}
		var row windowsResult
		err := c.Maintainer.request(ctx, "GET", "/api/v1/fleet/scripts/results/"+url.PathEscape(r.ExecutionID), nil, &row)
		if errors.Is(err, errNotFound) {
			return nil, true, nil
		}
		if err != nil {
			return nil, false, err
		}
		if row.ExitCode == nil {
			return nil, false, nil
		}
		if *row.ExitCode != 0 {
			if row.HostID != r.HostID || row.ExecutionID != r.ExecutionID || row.Script != r.Script {
				return nil, false, errors.New("unbound failed Windows execution")
			}
			if _, err = observed(row.CreatedAt, r, c.now(), age); err != nil {
				return nil, false, err
			}
			return nil, true, nil
		}
		ob, err := windowsObservation(row, r, c.Trust, c.now(), age)
		if err != nil {
			return nil, false, err
		}
		return &ob, true, nil
	}
	var response struct {
		Results []appleResult `json:"results"`
	}
	err := c.Maintainer.request(ctx, "GET", "/api/v1/fleet/commands/results?"+url.Values{"command_uuid": {r.UUID}}.Encode(), nil, &response)
	if errors.Is(err, errNotFound) {
		return nil, true, nil
	}
	if err != nil {
		return nil, false, err
	}
	if response.Results == nil {
		return nil, false, errors.New("missing Fleet MDM results")
	}
	var row *appleResult
	for i := range response.Results {
		candidate := &response.Results[i]
		if candidate.HostUUID != r.HostUUID || candidate.CommandUUID != r.UUID || candidate.RequestType != "CertificateList" {
			return nil, false, errors.New("fleet MDM results escape reserved target")
		}
		if row != nil {
			return nil, false, errors.New("duplicate Fleet MDM result")
		}
		row = candidate
	}
	if row == nil {
		return nil, false, nil
	}
	if row.Status == "Error" || row.Status == "CommandFormatError" {
		return nil, true, nil
	}
	if row.Status != "Acknowledged" {
		return nil, false, nil
	}
	ob, err := appleObservation(*row, r, c.Trust, c.now(), age)
	if err != nil {
		return nil, false, err
	}
	return &ob, true, nil
}

// ReconcileWindows never submits. Candidate execution IDs are hints only: each
// is read with the scoped maintainer credential and must prove the exact durable
// host, SYSTEM script nonce, enrollment and original timestamp. Multiple matches
// remain quarantined; no operator-supplied fingerprint can enter this path.
func (c *Collector) ReconcileWindows(ctx context.Context, device domain.DeviceID, command string, candidates []string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	_, binding, err := c.boundHost(ctx, device)
	if err != nil {
		return err
	}
	_, age, _, err := c.limits()
	if err != nil {
		return err
	}
	if len(candidates) == 0 || len(candidates) > 100 {
		return errors.New("invalid reconciliation candidate budget")
	}
	works, err := c.Repository.ListCollection(ctx, binding.Key)
	if err != nil {
		return err
	}
	for _, work := range works {
		var r reservation
		if json.Unmarshal(work.Payload, &r) != nil || r.UUID != command || r.Transport != "windows" || work.State != "quarantine" {
			continue
		}
		seen := map[string]bool{}
		var match *domain.CertificateObservation
		execution := ""
		for _, candidate := range candidates {
			if candidate == "" || len(candidate) > 256 || seen[candidate] {
				continue
			}
			seen[candidate] = true
			r.ExecutionID = candidate
			var row windowsResult
			err = c.Maintainer.request(ctx, "GET", "/api/v1/fleet/scripts/results/"+url.PathEscape(candidate), nil, &row)
			if errors.Is(err, errNotFound) {
				continue
			}
			if err != nil {
				return err
			}
			ob, e := windowsObservation(row, r, c.Trust, c.now(), age)
			if e != nil {
				continue
			}
			if match != nil {
				return errors.New("ambiguous authenticated script provenance")
			}
			match = &ob
			execution = candidate
		}
		if match == nil {
			return inventory.ErrPending
		}
		return c.Repository.RecordCollectionResult(ctx, work.ID, work.Generation, receiptJSON(collectionReceipt{ExecutionID: execution, Observation: match}), receiptJSON(map[string]any{"command_uuid": r.UUID, "host_id": r.HostID, "host_uuid": r.HostUUID, "execution_id": execution, "provenance_verified": true}))
	}
	return inventory.ErrPending
}

var canonicalOSVersion = regexp.MustCompile(`^(0|[1-9][0-9]{0,2})(\.(0|[1-9][0-9]{0,2})){0,2}$`)

func managedOnlySupported(platform, version string) bool {
	switch platform {
	case "darwin", "macos":
		for _, prefix := range []string{"macOS ", "Mac OS X "} {
			if strings.HasPrefix(version, prefix) {
				version = strings.TrimPrefix(version, prefix)
				break
			}
		}
	case "ios", "ipados":
		for _, prefix := range []string{"iOS ", "iPadOS "} {
			if strings.HasPrefix(version, prefix) {
				version = strings.TrimPrefix(version, prefix)
				break
			}
		}
	default:
		return false
	}
	if !canonicalOSVersion.MatchString(version) {
		return false
	}
	parts := strings.Split(version, ".")
	if len(parts) < 1 || len(parts) > 3 {
		return false
	}
	numbers := make([]int, len(parts))
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 || n > 1000 {
			return false
		}
		numbers[i] = n
	}
	major := numbers[0]
	switch platform {
	case "darwin", "macos":
		return major > 10 || (major == 10 && len(numbers) > 1 && numbers[1] >= 15)
	case "ios", "ipados":
		return major >= 13
	}
	return false
}

// prepareSelection derives the bounded pass from original shared reservation
// timestamps. Repeated terminal failures and process restarts cannot reset a
// host's priority to "never attempted". Result polling/receipt time is not used.
func (c *Collector) prepareSelection(ctx context.Context) error {
	cadence, _, budget, err := c.limits()
	if err != nil {
		return err
	}
	c.selected = map[domain.DeviceID]bool{}
	c.order = nil
	ids := make([]domain.DeviceID, 0, len(c.hosts))
	for id := range c.hosts {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	type candidate struct {
		id   domain.DeviceID
		last time.Time
	}
	candidates := []candidate{}
	for _, id := range ids {
		_, binding, err := c.boundHost(ctx, id)
		if errors.Is(err, inventory.ErrIneligible) {
			continue
		}
		if err != nil {
			return err
		}
		if c.Repository == nil {
			return errors.New("fleet collection requires durable repository")
		}
		works, err := c.Repository.ListCollection(ctx, binding.Key)
		if err != nil {
			return err
		}
		var last time.Time
		pending := 0
		unstarted, freshObservation := false, false
		for _, work := range works {
			if work.CreatedAt.After(last) {
				last = work.CreatedAt
			}
			var receipt collectionReceipt
			if len(work.Receipt) > 0 && json.Unmarshal(work.Receipt, &receipt) != nil {
				return errors.New("invalid durable Fleet collection receipt")
			}
			if work.State != "succeeded" || receipt.Pending {
				pending++
			}
			if work.State == "pending" || work.State == "leased" {
				unstarted = true
			}
			if receipt.Observation != nil && domain.Fresh(receipt.Observation.ObservedAt, c.now(), cadence) {
				freshObservation = true
			}
		}
		// Active/uncertain full budgets cannot consume selection slots. A previously
		// reserved but never-started claim may still be claimed/fenced, not resubmitted.
		due := pending < 2 && !freshObservation && (last.IsZero() || !last.Add(cadence).After(c.now()))
		if due || unstarted {
			candidates = append(candidates, candidate{id: id, last: last})
		}
	}
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].last.Equal(candidates[j].last) {
			return candidates[i].id < candidates[j].id
		}
		return candidates[i].last.Before(candidates[j].last)
	})
	for i, candidate := range candidates {
		c.order = append(c.order, candidate.id)
		if i < budget {
			c.selected[candidate.id] = true
		}
	}
	return nil
}

var _ inventory.CollectionOrderProvider = (*Collector)(nil)

func (c *Collector) CollectionOrder() []domain.DeviceID {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]domain.DeviceID{}, c.order...)
}
