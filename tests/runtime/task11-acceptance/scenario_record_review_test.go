package main

import (
	"testing"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/adoption"
)

// RSA renewal must select the original issued identity. A later adopted
// certificate remains a valid read-ca-issued selector but cannot replace that
// original credential for the immutable continuity attempt.
func TestScenarioSelectionRenewalRequiresOriginalIssuedPhase(t *testing.T) {
	for _, action := range []string{"nas-ca-adopted", "nas-ca-passive", "read-ca-issued"} {
		t.Run(action, func(t *testing.T) {
			root := recordFixture(t)
			store := recordOpen(t, root)
			at := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
			first := recordRequest(1, "nas-ca-original")
			first.Authority = "rsa"
			firstRaw := recordJSON(t, first)
			recordWrite(t, root, "requests", first, firstRaw)
			one, err := store.Admit(recordStage(first, firstRaw), first.Pins)
			if err != nil {
				t.Fatal(err)
			}
			original, originalSelection := recordIssuedFixture(t, first, firstRaw, at)
			if err := one.PublishResult(recordJSON(t, original)); err != nil {
				t.Fatal(err)
			}
			originalSelectionRaw := recordJSON(t, originalSelection)
			recordWrite(t, root, "ca-selections", first, originalSelectionRaw)

			second := recordRequest(2, "nas-ca-adopted")
			second.Authority, second.IssuanceSequence, second.SelectionSHA256 = "rsa", 1, adoption.Digest(originalSelectionRaw)
			secondRaw := recordJSON(t, second)
			recordWrite(t, root, "requests", second, secondRaw)
			two, err := store.Admit(recordStage(second, secondRaw), second.Pins)
			if err != nil {
				t.Fatal(err)
			}
			adopted, selection := recordIssuedFixture(t, second, secondRaw, at.Add(2*time.Second))
			adopted.CA.Phase, adopted.CA.Peer = "adopted", "10.203.11.21"
			adoptedRaw := recordJSON(t, adopted)
			if err := two.PublishResult(adoptedRaw); err != nil {
				t.Fatal("control adopted issuance must otherwise be valid", err)
			}
			selection.IssuanceSequence, selection.ResultSHA256 = 2, adoption.Digest(adoptedRaw)
			selectionRaw := recordJSON(t, selection)
			recordWrite(t, root, "ca-selections", second, selectionRaw)

			third := recordRequest(3, action)
			third.IssuanceSequence, third.SelectionSHA256 = 2, adoption.Digest(selectionRaw)
			if action != "read-ca-issued" {
				third.Authority = "rsa"
			}
			thirdRaw := recordJSON(t, third)
			recordWrite(t, root, "requests", third, thirdRaw)
			three, err := store.Admit(recordStage(third, thirdRaw), third.Pins)
			if err != nil {
				t.Fatal(err)
			}
			_, selected, err := three.ReadCASelection()
			if action == "read-ca-issued" {
				if err != nil || selected != selection {
					t.Fatal("read-only adopted CA row selection refused", err)
				}
			} else if err == nil {
				t.Fatal("renewal selected adopted issuance instead of immutable original identity")
			}
		})
	}
}
