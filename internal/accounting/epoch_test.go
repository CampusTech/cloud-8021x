package accounting

import (
	"testing"
	"time"
)

func TestCollectionEpochConservativeBaseline(t *testing.T) {
	epoch := time.Unix(1800000000, 0)
	for _, status := range []string{"Interim-Update", "Stop"} {
		t.Run(status, func(t *testing.T) {
			e := Event{Status: status, Received: epoch, Duration: 900, Upload: 10000, Download: 20000, Bits: 64, Marked: true}
			state, interval, reason := ApplyEpoch(State{}, e, epoch)
			if interval != nil || reason != "baseline" || state.Upload != 10000 {
				t.Fatalf("historical usage credited: %+v %s", interval, reason)
			}
			e.Received = epoch.Add(time.Second)
			e.Duration += 10
			e.Upload += 5
			e.Download += 7
			_, interval, _ = ApplyEpoch(state, e, epoch)
			if status == "Stop" {
				if interval != nil {
					t.Fatal("stopped session reopened")
				}
			} else if interval == nil || interval.Upload != 5 || interval.Download != 7 || interval.Seconds != 10 {
				t.Fatalf("wrong delta: %+v", interval)
			}
		})
	}
	start := Event{Status: "Start", Received: epoch, Bits: 64, Marked: true}
	state, _, _ := ApplyEpoch(State{}, start, epoch)
	next := Event{Status: "Interim-Update", Received: epoch.Add(time.Minute), Duration: 60, Upload: 9, Download: 8, Bits: 64, Marked: true}
	_, delta, _ := ApplyEpoch(state, next, epoch)
	if delta == nil || delta.Upload != 9 || delta.Seconds != 60 {
		t.Fatal("new Start did not establish normal zero baseline")
	}
	state2, delta, reason := ApplyEpoch(state, Event{Status: "Stop", Received: epoch.Add(-time.Second), Duration: 999, Upload: 999}, epoch)
	if delta != nil || reason != "before_collection_epoch" || state2 != state {
		t.Fatal("pre-epoch record moved state")
	}
}
