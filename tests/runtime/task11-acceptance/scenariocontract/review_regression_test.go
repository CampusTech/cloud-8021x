package scenariocontract

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/CampusTech/cloud-8021x/internal/accounting"
)

func TestCanonicalWireKeysRejectCaseFoldedAliasesAndSemanticDuplicates(t *testing.T) {
	r := validRequest("probe-active-pair")
	request := string(encodeRequest(t, r))
	for name, bad := range map[string]string{
		"irrelevant-empty-node":     strings.Replace(request, `"schema":1`, `"schema":1,"Node":""`, 1),
		"irrelevant-empty-sessions": strings.Replace(request, `"schema":1`, `"schema":1,"Sessions":[]`, 1),
		"duplicate-sequence":        strings.Replace(request, `"sequence":1`, `"sequence":1,"Sequence":2`, 1),
		"aliased-pin":               strings.Replace(request, `"plan_sha256"`, `"PLAN_SHA256"`, 1),
	} {
		t.Run("request/"+name, func(t *testing.T) {
			if _, e := DecodeRequest([]byte(bad)); e == nil {
				t.Fatal("case-folded wire key accepted")
			}
		})
	}
	t.Run("stage", func(t *testing.T) {
		if _, e := DecodeStage([]byte(`{"stage":"keys"}`)); e != nil {
			t.Fatal("canonical fixed stage refused", e)
		}
		for _, bad := range []string{`{"Stage":"keys"}`, `{"stage":"keys","Stage":"keys"}`} {
			if _, e := DecodeStage([]byte(bad)); e == nil {
				t.Fatal("aliased fixed stage accepted")
			}
		}
	})
	r = validRequest("read-accounting")
	r.Node = "green-primary"
	r.Sessions = []string{"task11-chosen"}
	v := resultFor(r)
	l := validLedger(r)
	v.Ledger = &l
	encoded, e := json.Marshal(v)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = DecodeResult(encoded, r, v.RequestSHA256); e != nil {
		t.Fatal("canonical production accounting fields refused", e)
	}
	result := string(encoded)
	for name, bad := range map[string]string{
		"irrelevant-null-body": strings.Replace(result, `"kind":"scenario-operation"`, `"kind":"scenario-operation","Probe":null`, 1),
		"nested-ledger":        strings.Replace(result, `"read_only":true`, `"Read_Only":true`, 1),
		"production-state":     strings.Replace(result, `"Upload":`, `"upload":`, 1),
		"nested-attempt":       strings.Replace(result, `"generation":1`, `"Generation":1`, 1),
		"opaque-array":         strings.Replace(result, `"payload":"`+base64.StdEncoding.EncodeToString(l.Outbox[0].Payload)+`"`, `"payload":[123,125]`, 1),
	} {
		t.Run("result/"+name, func(t *testing.T) {
			if bad == result {
				t.Fatal("regression did not change the actual result")
			}
			if _, e := DecodeResult([]byte(bad), r, v.RequestSHA256); e == nil {
				t.Fatal("noncanonical nested or opaque wire value accepted")
			}
		})
	}
	probeRequest := validRequest("probe-active-pair")
	probe := resultFor(probeRequest)
	probe.Probe = &PairObservation{Nodes: map[string]NodeObservation{"green-primary": validNode("green-primary", 1), "green-secondary": validNode("green-secondary", 2)}}
	encoded, e = json.Marshal(probe)
	if e != nil {
		t.Fatal(e)
	}
	t.Run("nested-map-unit", func(t *testing.T) {
		bad := strings.Replace(string(encoded), `"main_pid":400`, `"Main_PID":400`, 1)
		if bad == string(encoded) {
			t.Fatal("regression did not change the actual unit observation")
		}
		if _, e := DecodeResult([]byte(bad), probeRequest, probe.RequestSHA256); e == nil {
			t.Fatal("aliased nested map value field accepted")
		}
	})
	pin := strings.Repeat("a", 64)
	selection := CASelection{Schema: 1, AttemptID: probeRequest.AttemptID, IssuanceSequence: 1, ResultSHA256: pin, Authority: "ec", Serial: "1234", LeafDERSHA256: pin, OriginalRootSHA256: pin, OriginalIntermediateSHA256: pin}
	encoded, e = json.Marshal(selection)
	if e != nil {
		t.Fatal(e)
	}
	t.Run("ca-selection", func(t *testing.T) {
		if _, e := DecodeCASelection(encoded); e != nil {
			t.Fatal("canonical CA selection refused", e)
		}
		for _, bad := range []string{strings.Replace(string(encoded), `"serial"`, `"Serial"`, 1), strings.Replace(string(encoded), `"serial":"1234"`, `"serial":"1234","Serial":"1235"`, 1)} {
			if _, e := DecodeCASelection([]byte(bad)); e == nil {
				t.Fatal("aliased CA selection accepted")
			}
		}
	})
}

func TestUsageIntervalCannotReferenceAnotherSelectedSessionsEvent(t *testing.T) {
	r := validRequest("read-accounting")
	r.Node = "green-primary"
	r.Sessions = []string{"task11-chosen", "task11-other"}
	v := resultFor(r)
	l := validLedger(r)
	other := [4]string{"10.203.11.40", "10.203.11.40", "020000000040", "task11-other"}
	otherKey := accounting.SessionKey(other)
	l.Sessions = append(l.Sessions, SessionObservation{SessionKey: otherKey, State: l.Sessions[0].State})
	secondEvent := l.Observations[0]
	secondEvent.EventID = strings.Repeat("b", 64)
	secondEvent.IntakeID = 2
	secondEvent.SessionKey = otherKey
	secondEvent.Event.ID = secondEvent.EventID
	secondEvent.Event.Key = other
	l.Observations = append(l.Observations, secondEvent)
	l.Intervals = []IntervalObservation{
		{UsageID: strings.Repeat("f", 64), EventID: l.Observations[0].EventID, SessionKey: l.Observations[0].SessionKey, Interval: accounting.Interval{ID: strings.Repeat("f", 64), Key: l.Observations[0].Event.Key}},
		{UsageID: strings.Repeat("c", 64), EventID: secondEvent.EventID, SessionKey: otherKey, Interval: accounting.Interval{ID: strings.Repeat("c", 64), Key: other}},
	}
	v.Ledger = &l
	raw, e := json.Marshal(v)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = DecodeResult(raw, r, v.RequestSHA256); e != nil {
		t.Fatal("valid separate selected-session associations refused", e)
	}
	l.Intervals[1].EventID = l.Observations[0].EventID
	raw, e = json.Marshal(v)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = DecodeResult(raw, r, v.RequestSHA256); e == nil {
		t.Fatal("usage interval linked to a different selected session's event")
	}
}
