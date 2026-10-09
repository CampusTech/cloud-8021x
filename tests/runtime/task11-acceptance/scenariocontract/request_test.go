package scenariocontract

import (
	"encoding/json"
	"strings"
	"testing"
)

func validRequest(action string) Request {
	p := strings.Repeat("a", 64)
	r := Request{Schema: 1, AttemptID: "task11-" + strings.Repeat("b", 32), Sequence: 1, Action: action, Pins: Pins{p, p, p, p, p}}
	if bodyKind(action) == "ca" {
		r.Authority = "ec"
	}
	return r
}
func encodeRequest(t *testing.T, r Request) []byte {
	t.Helper()
	b, e := json.Marshal(r)
	if e != nil {
		t.Fatal(e)
	}
	return b
}

func TestClosedRequests(t *testing.T) {
	for _, action := range []string{"probe-active-pair", "nas-native", "nas-ongoing", "nas-duplicates", "nas-outage", "nas-ca-original", "nas-ca-adopted", "nas-ca-passive", "stop-postgres", "start-postgres", "intake-unavailable", "intake-ready", "probe-owned-cleanup"} {
		t.Run(action, func(t *testing.T) {
			r := validRequest(action)
			got, e := DecodeRequest(encodeRequest(t, r))
			if e != nil || got.Action != action {
				t.Fatalf("valid closed action refused: %v", e)
			}
		})
	}
	for _, action := range []string{"stop-green-primary", "start-green-primary", "reboot-green-primary"} {
		r := validRequest(action)
		r.Node = "green-primary"
		if _, e := DecodeRequest(encodeRequest(t, r)); e != nil {
			t.Fatalf("closed primary lifecycle refused: %v", e)
		}
	}
	r := validRequest("read-accounting")
	r.Node = "green-secondary"
	r.Sessions = []string{"task11-new", "task11-ongoing"}
	if _, e := DecodeRequest(encodeRequest(t, r)); e != nil {
		t.Fatal(e)
	}
	r = validRequest("read-ca-issued")
	r.Sequence = 3
	r.SelectionSHA256 = strings.Repeat("c", 64)
	r.IssuanceSequence = 2
	if _, e := DecodeRequest(encodeRequest(t, r)); e != nil {
		t.Fatal(e)
	}
}
func TestRequestRejectsAmbiguousOrUnboundedInputs(t *testing.T) {
	base := validRequest("probe-active-pair")
	tests := map[string]func(*Request){
		"schema": func(r *Request) { r.Schema = 2 }, "unknown-action": func(r *Request) { r.Action = "run" },
		"attempt-path":      func(r *Request) { r.AttemptID = "../task11-" + strings.Repeat("b", 32) },
		"uppercase-attempt": func(r *Request) { r.AttemptID = "task11-" + strings.Repeat("B", 32) },
		"sequence-zero":     func(r *Request) { r.Sequence = 0 }, "sequence-bound": func(r *Request) { r.Sequence = 25 },
		"missing-plan": func(r *Request) { r.PlanSHA256 = "" }, "bad-platform": func(r *Request) { r.PlatformSHA256 = strings.Repeat("A", 64) },
		"missing-enrollment": func(r *Request) { r.EnrollmentSHA256 = "" }, "missing-app": func(r *Request) { r.ApplicationSHA256 = "" }, "missing-helper": func(r *Request) { r.ScenarioSHA256 = "" },
		"irrelevant-node": func(r *Request) { r.Node = "green-primary" }, "irrelevant-sessions": func(r *Request) { r.Sessions = []string{"task11-one"} },
		"irrelevant-selection": func(r *Request) { r.SelectionSHA256 = strings.Repeat("d", 64) }, "irrelevant-issuance": func(r *Request) { r.IssuanceSequence = 1 },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			r := base
			mutate(&r)
			if _, e := DecodeRequest(encodeRequest(t, r)); e == nil {
				t.Fatal("invalid request accepted")
			}
		})
	}
	b := string(encodeRequest(t, base))
	for _, raw := range []string{strings.Replace(b, `"schema":1`, `"schema":1,"schema":1`, 1), strings.Replace(b, `"schema":1`, `"schema":1,"argv":["true"]`, 1), b + " {}", strings.Replace(b, `"sequence":1`, `"sequence":1.0`, 1), strings.Repeat(" ", MaxRequestBytes) + b, strings.Replace(b, `"action":"probe-active-pair"`, `"action":"probe-active-pair","sessions":[]`, 1)} {
		if _, e := DecodeRequest([]byte(raw)); e == nil {
			t.Fatal("ambiguous or unbounded JSON accepted")
		}
	}
}
func TestAccountingSelectors(t *testing.T) {
	r := validRequest("read-accounting")
	r.Node = "green-primary"
	r.Sessions = []string{"task11-one"}
	for _, mutate := range []func(*Request){func(r *Request) { r.Node = "blue-primary" }, func(r *Request) { r.Sessions = nil }, func(r *Request) { r.Sessions = []string{"task11-one", "task11-one"} }, func(r *Request) { r.Sessions = []string{"task11-one;select"} }, func(r *Request) { r.Sessions = []string{"task11-"} }, func(r *Request) { r.Sessions = []string{"task11-" + strings.Repeat("a", 58)} }, func(r *Request) {
		r.Sessions = []string{"task11-1", "task11-2", "task11-3", "task11-4", "task11-5", "task11-6", "task11-7", "task11-8", "task11-9"}
	}} {
		c := r
		mutate(&c)
		if _, e := DecodeRequest(encodeRequest(t, c)); e == nil {
			t.Fatal("unsafe accounting selection accepted")
		}
	}
}
func TestLifecycleAndCASelectionAreClosed(t *testing.T) {
	r := validRequest("start-green-primary")
	r.Node = "green-secondary"
	if r.Validate() == nil {
		t.Fatal("secondary control accepted")
	}
	r = validRequest("read-ca-issued")
	r.Sequence = 3
	r.IssuanceSequence = 2
	r.SelectionSHA256 = strings.Repeat("d", 64)
	for _, mutate := range []func(*Request){func(r *Request) { r.IssuanceSequence = 0 }, func(r *Request) { r.IssuanceSequence = 3 }, func(r *Request) { r.SelectionSHA256 = "" }, func(r *Request) { r.Node = "blue-primary" }} {
		c := r
		mutate(&c)
		if c.Validate() == nil {
			t.Fatal("unsafe CA selection accepted")
		}
	}
}
func TestStageRequestHasIndependentPinAndDerivedName(t *testing.T) {
	r := validRequest("probe-active-pair")
	r.Sequence = 24
	got, e := r.RecordName()
	if e != nil || got != r.AttemptID+"-24.json" {
		t.Fatalf("derived fixed basename: %q %v", got, e)
	}
	valid := `{"stage":"scenario-operation","attempt_id":"` + r.AttemptID + `","sequence":24,"request_sha256":"` + strings.Repeat("d", 64) + `"}`
	s, e := DecodeStage([]byte(valid))
	if e != nil || s.Sequence != 24 {
		t.Fatalf("valid independently pinned stage: %v", e)
	}
	for _, raw := range []string{`{"stage":"scenario-operation"}`, strings.Replace(valid, `"sequence":24`, `"sequence":25`, 1), strings.Replace(valid, `"request_sha256"`, `"plan_sha256"`, 1), strings.Replace(valid, `"stage":"scenario-operation"`, `"stage":"scenario-operation","stage":"scenario-operation"`, 1), `{"stage":"keys","attempt_id":"` + r.AttemptID + `"}`, `{"stage":"run"}`} {
		if _, e := DecodeStage([]byte(raw)); e == nil {
			t.Fatal("unsafe stage accepted")
		}
	}
	for _, stage := range []string{"keys", "prepare", "cutover", "deactivate", "proofs", "resume", "observe", "recover", "verify-cloud"} {
		if _, e := DecodeStage([]byte(`{"stage":"` + stage + `"}`)); e != nil {
			t.Fatal(e)
		}
	}
}
