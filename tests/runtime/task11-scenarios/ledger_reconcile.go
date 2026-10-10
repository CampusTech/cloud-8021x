package main

import (
	"bytes"
	"errors"
	"reflect"
	"slices"
	"strings"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/accounting"
	"github.com/CampusTech/cloud-8021x/internal/accounting/binding"
	sc "github.com/CampusTech/cloud-8021x/tests/runtime/task11-acceptance/scenariocontract"
)

// Inputs are the immutable independently pinned plan, the retired pinned NAS
// result whose expectations predate sends, and the selected read-only SQL rows.
// No values are reconstructed from intake or from delivery success flags.
func reconcileNativeLedger(p nasPrivatePlan, nas sc.NASResult, l sc.LedgerObservation) error {
	fail := func() error { return errors.New("selected native ledger differs from independent expectation") }
	plan := p.Scenario
	if validatePlan(plan) != nil || l.Deployment != "task11-green" || l.Database != "cloud8021x_task11_green" || !l.ReadOnly || l.Isolation != "repeatable-read" || !l.Epoch.Equal(plan.CollectionEpoch) || !shaPattern.MatchString(l.ConfigSHA256) || !nas.EAP.Accepted || nas.EAP.Rejected || nas.EAP.TunnelType != 13 || nas.EAP.TunnelMediumType != 6 || nas.EAP.VLAN != 120 || nas.Peer != plan.Target || nas.Session != plan.Session || nas.Station != p.Station || nas.Attribution.Fingerprint != p.ClientLeafSHA256 || nas.Attribution.DeviceID != "fleet:1" || nas.Attribution.VLAN == nil || *nas.Attribution.VLAN != 120 || !shaPattern.MatchString(nas.ClassSHA256) {
		return fail()
	}
	one := func(v string) accounting.Attribute { return accounting.Attribute{Value: v, Count: 1} }
	key, err := accounting.CanonicalKey(accounting.Raw{SourceIP: plan.NAS, NASIP: one(plan.NAS), Station: one(p.Station), Session: one(plan.Session)})
	if err != nil {
		return fail()
	}
	session := accounting.SessionKey(key)
	multiplier := 1
	if plan.Scenario == "duplicate-pair" {
		multiplier = 2
	}
	if len(nas.Packets) != len(plan.Events)*multiplier || len(l.Observations) != len(nas.Expected.EventIDs) || len(l.Intervals) != len(nas.Expected.UsageIDs) || len(l.Sessions) != 1 || l.Sessions[0].SessionKey != session || l.Sessions[0].Pending || l.Sessions[0].NativeBaselineRequired {
		return fail()
	}
	for i, packet := range nas.Packets {
		event := plan.Events[i/multiplier]
		peer := plan.Target
		if multiplier == 2 {
			peer = []string{"10.203.11.21", "10.203.11.22"}[i%2]
		}
		if packet.Peer != peer || packet.Status != event.Status || packet.Duration != event.Duration || packet.UploadBytes != event.Upload || packet.DownloadBytes != event.Download || packet.SentAt.Before(nas.ChosenAt) || packet.CompletedAt.Before(packet.SentAt) || packet.CompletedAt.Sub(packet.SentAt) > 4*time.Second || len(packet.RequestAuthenticator) != 32 || (plan.Scenario != "postgres-outage" && !packet.ACK) {
			return fail()
		}
		if multiplier == 2 && i%2 == 1 {
			previous := nas.Packets[i-1]
			if packet.PacketID != previous.PacketID || packet.RequestAuthenticator != previous.RequestAuthenticator {
				return fail()
			}
		}
	}
	observed := map[string]sc.EventObservation{}
	for _, v := range l.Observations {
		if _, exists := observed[v.EventID]; exists {
			return fail()
		}
		observed[v.EventID] = v
	}
	intervals := map[string]sc.IntervalObservation{}
	for _, v := range l.Intervals {
		if _, exists := intervals[v.UsageID]; exists {
			return fail()
		}
		intervals[v.UsageID] = v
	}
	state := accounting.State{}
	var upload, download, seconds uint64
	eventIndex := 0
	usageIDs := []string{}
	workPayload := map[string]any{}
	seen := map[string]bool{}
	for _, eventID := range nas.Expected.EventIDs {
		if !shaPattern.MatchString(eventID) || seen[eventID] {
			return fail()
		}
		seen[eventID] = true
		observation, ok := observed[eventID]
		if !ok || observation.EventID != observation.Event.ID || observation.SessionKey != session || observation.IntakeID < 1 || !observation.ReceivedAt.Equal(observation.Event.Received) {
			return fail()
		}
		event := observation.Event
		// Correspond the independently planned counter tuple to actual packet(s),
		// including the whole-second native timestamp's truncation interval.
		for eventIndex < len(plan.Events) {
			candidate := plan.Events[eventIndex]
			status := map[int]string{1: "Start", 2: "Stop", 3: "Interim-Update"}[candidate.Status]
			if event.Status == status && event.Duration == uint64(candidate.Duration) && event.Upload == candidate.Upload && event.Download == candidate.Download {
				break
			}
			eventIndex++
		}
		if eventIndex >= len(plan.Events) || event.Key != key || event.Bits != 64 || !event.Marked || event.Location != "task11" || event.TerminateCause != "N/A" || event.CalledStation != "" || event.NASPort != "" || event.AttributionIssue != "" || event.Identity == nil || !sameLedgerAttribution(event.Identity, &nas.Attribution) {
			return fail()
		}
		within := false
		for j := 0; j < multiplier; j++ {
			packet := nas.Packets[eventIndex*multiplier+j]
			host := "task11-green-primary"
			if packet.Peer == "10.203.11.22" {
				host = "task11-green-secondary"
			}
			if event.Host == host && !event.Received.Before(packet.SentAt.Truncate(time.Second)) && !event.Received.After(packet.CompletedAt) {
				within = true
			}
		}
		if !within {
			return fail()
		}
		eventIndex++
		next, interval, reason := accounting.ApplyEpoch(state, event, plan.CollectionEpoch)
		state = next
		if reason != observation.Reason {
			return fail()
		}
		workPayload["accounting:"+eventID] = event
		if interval != nil {
			actual, ok := intervals[interval.ID]
			if !ok || actual.EventID != eventID || actual.SessionKey != session || !sameLedgerInterval(actual.Interval, *interval) {
				return fail()
			}
			usageIDs = append(usageIDs, interval.ID)
			upload += interval.Upload
			download += interval.Download
			seconds += interval.Seconds
			workPayload["usage:"+interval.ID] = *interval
		}
	}
	if !slices.Equal(usageIDs, nas.Expected.UsageIDs) || upload != nas.Expected.UploadBytes || download != nas.Expected.DownloadBytes || seconds != nas.Expected.Seconds || !sameLedgerState(l.Sessions[0].State, state) || len(l.Outbox) != len(workPayload) {
		return fail()
	}
	used := map[string]bool{}
	for _, w := range l.Outbox {
		expected, exists := workPayload[w.ID]
		if !exists || used[w.ID] || w.Kind != "outbox" || w.CreatedAt.IsZero() || len(w.Payload) == 0 {
			return fail()
		}
		used[w.ID] = true
		// Decode for semantic comparison only; preserve the original stored byte
		// slice, including PostgreSQL JSON whitespace and all uint64 values.
		if strings.HasPrefix(w.ID, "accounting:") {
			var body accounting.Event
			want, ok := expected.(accounting.Event)
			if !ok || strictJSON(w.Payload, 1<<20, &body) != nil || !sameLedgerEvent(body, want) {
				return fail()
			}
		} else {
			var body accounting.Interval
			want, ok := expected.(accounting.Interval)
			if !ok || strictJSON(w.Payload, 1<<20, &body) != nil || !sameLedgerInterval(body, want) {
				return fail()
			}
		}
	}
	return nil
}
func preserveLedgerWork(before, after sc.LedgerObservation) error {
	if before.Deployment != after.Deployment || before.Database != after.Database || !before.Epoch.Equal(after.Epoch) || before.ConfigSHA256 != after.ConfigSHA256 || !sameLedgerRows(before, after) || len(before.Outbox) != len(after.Outbox) {
		return errors.New("preserved native ledger identity or rows changed")
	}
	stored := map[string]sc.WorkObservation{}
	for _, w := range before.Outbox {
		if _, ok := stored[w.ID]; ok {
			return errors.New("duplicate preserved work")
		}
		stored[w.ID] = w
	}
	seen := map[string]bool{}
	for _, w := range after.Outbox {
		old, ok := stored[w.ID]
		if !ok || seen[w.ID] || w.Kind != old.Kind || !bytes.Equal(w.Payload, old.Payload) || !w.CreatedAt.Equal(old.CreatedAt) {
			return errors.New("original outbox bytes or creation timestamp changed")
		}
		seen[w.ID] = true
		if len(old.Receipt) > 0 && !bytes.Equal(old.Receipt, w.Receipt) {
			return errors.New("original delivery receipt changed")
		}
		if len(w.Attempts) < len(old.Attempts) {
			return errors.New("original attempt evidence disappeared")
		}
		for i, prior := range old.Attempts {
			current := w.Attempts[i]
			if prior.Generation != current.Generation || prior.Owner != current.Owner || !prior.StartedAt.Equal(current.StartedAt) {
				return errors.New("original attempt immutable identity changed")
			}
			if prior.FinishedAt != nil && !sameLedgerAttempt(prior, current) {
				return errors.New("original completed attempt evidence changed")
			}
			if prior.Outcome != nil && !reflect.DeepEqual(prior.Outcome, current.Outcome) {
				return errors.New("original attempt outcome changed")
			}
			if len(prior.Receipt) > 0 && !bytes.Equal(prior.Receipt, current.Receipt) {
				return errors.New("original attempt receipt changed")
			}
		}
		if len(old.RecoveryEvidence) > 0 && !bytes.Equal(old.RecoveryEvidence, w.RecoveryEvidence) {
			return errors.New("original recovery evidence changed")
		}
		if old.State == "succeeded" && w.State != "succeeded" {
			return errors.New("original delivery success regressed")
		}
	}
	return nil
}

// Typed records compare timestamp instants; location pointers and monotonic
// clock metadata do not survive PostgreSQL/JSON. All other fields remain exact.
// These helpers do not modify records or opaque stored payload/receipt bytes.
func sameLedgerAttribution(a, b *binding.Attribution) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	x, y := *a, *b
	if !x.IssuedAt.Equal(y.IssuedAt) {
		return false
	}
	x.IssuedAt, y.IssuedAt = time.Time{}, time.Time{}
	return reflect.DeepEqual(x, y)
}
func sameLedgerEvent(a, b accounting.Event) bool {
	if !a.Received.Equal(b.Received) || !sameLedgerAttribution(a.Identity, b.Identity) {
		return false
	}
	a.Received, b.Received = time.Time{}, time.Time{}
	a.Identity, b.Identity = nil, nil
	return reflect.DeepEqual(a, b)
}
func sameLedgerState(a, b accounting.State) bool {
	if !a.LastSeen.Equal(b.LastSeen) || !sameLedgerAttribution(a.Identity, b.Identity) {
		return false
	}
	a.LastSeen, b.LastSeen = time.Time{}, time.Time{}
	a.Identity, b.Identity = nil, nil
	return reflect.DeepEqual(a, b)
}
func sameLedgerInterval(a, b accounting.Interval) bool {
	if !a.Received.Equal(b.Received) || !sameLedgerAttribution(a.Identity, b.Identity) {
		return false
	}
	a.Received, b.Received = time.Time{}, time.Time{}
	a.Identity, b.Identity = nil, nil
	return reflect.DeepEqual(a, b)
}
func sameLedgerAttempt(a, b sc.AttemptObservation) bool {
	if !a.StartedAt.Equal(b.StartedAt) || (a.FinishedAt == nil) != (b.FinishedAt == nil) {
		return false
	}
	if a.FinishedAt != nil && !a.FinishedAt.Equal(*b.FinishedAt) {
		return false
	}
	a.StartedAt, b.StartedAt = time.Time{}, time.Time{}
	a.FinishedAt, b.FinishedAt = nil, nil
	return reflect.DeepEqual(a, b)
}
func sameLedgerRows(a, b sc.LedgerObservation) bool {
	if len(a.Sessions) != len(b.Sessions) || len(a.Observations) != len(b.Observations) || len(a.Intervals) != len(b.Intervals) || (a.Sessions == nil) != (b.Sessions == nil) || (a.Observations == nil) != (b.Observations == nil) || (a.Intervals == nil) != (b.Intervals == nil) {
		return false
	}
	for i, x := range a.Sessions {
		y := b.Sessions[i]
		if !sameLedgerState(x.State, y.State) {
			return false
		}
		x.State, y.State = accounting.State{}, accounting.State{}
		if !reflect.DeepEqual(x, y) {
			return false
		}
	}
	for i, x := range a.Observations {
		y := b.Observations[i]
		if !x.ReceivedAt.Equal(y.ReceivedAt) || !sameLedgerEvent(x.Event, y.Event) {
			return false
		}
		x.ReceivedAt, y.ReceivedAt = time.Time{}, time.Time{}
		x.Event, y.Event = accounting.Event{}, accounting.Event{}
		if !reflect.DeepEqual(x, y) {
			return false
		}
	}
	for i, x := range a.Intervals {
		y := b.Intervals[i]
		if !sameLedgerInterval(x.Interval, y.Interval) {
			return false
		}
		x.Interval, y.Interval = accounting.Interval{}, accounting.Interval{}
		if !reflect.DeepEqual(x, y) {
			return false
		}
	}
	return true
}
