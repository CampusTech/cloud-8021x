package scenariocontract

import (
	"strings"
	"testing"
	"time"
)

func completionFor(r Request) Completion {
	v := resultFor(r)
	v.Gate = &GateObservation{State: "intake-ready", ObservedAt: v.StartedAt}
	return Completion{Request: r, RequestSHA256: v.RequestSHA256, Result: v}
}
func TestSequenceRequiresEveryActualRetiredPredecessor(t *testing.T) {
	r := validRequest("intake-ready")
	if e := ValidateHistory(r, nil); e != nil {
		t.Fatal(e)
	}
	first := completionFor(r)
	r.Sequence = 2
	if e := ValidateHistory(r, []Completion{first}); e != nil {
		t.Fatal(e)
	}
	second := completionFor(r)
	second.Result.StartedAt = first.Result.FinishedAt
	second.Result.FinishedAt = second.Result.StartedAt.Add(time.Second)
	r.Sequence = 3
	if e := ValidateHistory(r, []Completion{first, second}); e != nil {
		t.Fatal(e)
	}
	for _, history := range [][]Completion{nil, {first}, {second, first}, {first, first}, {first, second, second}} {
		if e := ValidateHistory(r, history); e == nil {
			t.Fatal("missing, duplicated or reordered history accepted")
		}
	}
	for _, mutate := range []func(*Completion){func(c *Completion) { c.Result.Retired = false }, func(c *Completion) { c.Request.AttemptID = "task11-" + strings.Repeat("c", 32) }, func(c *Completion) { c.Request.EnrollmentSHA256 = strings.Repeat("d", 64) }, func(c *Completion) { c.RequestSHA256 = strings.Repeat("e", 64) }, func(c *Completion) { c.Result.FinishedAt = c.Result.StartedAt.Add(-time.Second) }} {
		h := []Completion{first, second}
		mutate(&h[0])
		if e := ValidateHistory(r, h); e == nil {
			t.Fatal("uncertain/substituted predecessor accepted")
		}
	}
	r.Sequence = 1
	if e := ValidateHistory(r, []Completion{first}); e == nil {
		t.Fatal("retained attempt replayed")
	}
}
