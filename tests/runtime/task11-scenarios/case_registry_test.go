package main

import (
	"reflect"
	"testing"
)

func TestClosedCaseFilenameRegistryKeepsDistinctIrreversibleCases(t *testing.T) {
	wanted := map[string][]string{
		"native-accounting": {"native-accounting.json"},
		"ongoing-baseline":  {"ongoing-interim.json", "ongoing-stop.json"},
		"duplicate-pair":    {"duplicate-pair.json"},
		"ha-primary":        {"ha-primary.json"},
		"postgres-outage":   {"postgres-outage.json"},
		"business-outage":   {"business-outage.json"},
		"ca-continuity":     {"ca-ec-continuity.json", "ca-rsa-continuity.json"},
	}
	for command, files := range wanted {
		actual, e := closedCaseFiles(command)
		if e != nil {
			t.Fatal(e)
		}
		if !reflect.DeepEqual(actual, files) {
			t.Fatal("reviewed cases omitted/reordered or filename override accepted")
		}
		actual[0] = "changed.json"
		again, e := closedCaseFiles(command)
		if e != nil || !reflect.DeepEqual(again, files) {
			t.Fatal("caller mutated closed registry")
		}
	}
	for _, unknown := range []string{"", "../native-accounting", "arbitrary-command", "native-accounting.json"} {
		if _, e := closedCaseFiles(unknown); e == nil {
			t.Fatal("unknown case/path override accepted")
		}
	}
}
func TestCAOuterPhaseIsExplicitAndNeverAControllerFSM(t *testing.T) {
	for _, phase := range []string{"original", "adopted", "passive"} {
		if e := validateOuterCAPhase("ca-continuity", phase); e != nil {
			t.Fatal(e)
		}
	}
	for _, phase := range []string{"", "active", "prepare", "cutover", "../../outside"} {
		if validateOuterCAPhase("ca-continuity", phase) == nil {
			t.Fatal("unknown/implicit controller phase accepted")
		}
	}
	if e := validateOuterCAPhase("native-accounting", ""); e != nil {
		t.Fatal(e)
	}
	if validateOuterCAPhase("native-accounting", "adopted") == nil {
		t.Fatal("irrelevant CA phase accepted")
	}
}
