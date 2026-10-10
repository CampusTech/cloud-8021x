package main

import (
	"bytes"
	"errors"
	"testing"
)

func TestPrepareRequiresCompleteFixedInputs(t *testing.T) {
	if _, e := prepareNASBundle(producerInputs{}); e == nil {
		t.Fatal("empty protected source accepted")
	}
}
func TestPreparedPublicationIsExclusiveAndRetainsFailure(t *testing.T) {
	b := preparedNAS{Materials: map[string][]byte{}, Plans: map[string][]byte{}}
	for _, n := range nasMaterialNames {
		b.Materials[n] = []byte("synthetic " + n)
	}
	for _, n := range []string{"native-accounting", "ongoing-interim", "ongoing-stop", "duplicate-pair", "ha-primary", "postgres-outage", "business-outage", "ca-ec-continuity", "ca-rsa-continuity"} {
		b.Plans[n+".json"] = []byte("private " + n)
	}
	var got []string
	e := publishPreparedNAS(b, func(kind, name string, raw []byte) error {
		got = append(got, kind+"/"+name)
		if !bytes.Equal(raw, b.Materials[name]) && !bytes.Equal(raw, b.Plans[name]) {
			t.Fatal("changed bytes")
		}
		return nil
	})
	if e != nil || len(got) != 22 {
		t.Fatalf("closed22 publication absent: %v %d", e, len(got))
	}
	got = nil
	injected := errors.New("injected exclusive write failure")
	e = publishPreparedNAS(b, func(kind, name string, raw []byte) error {
		got = append(got, kind+"/"+name)
		if len(got) == 3 {
			return injected
		}
		return nil
	})
	if !errors.Is(e, injected) || len(got) != 3 {
		t.Fatal("partial state continued or failure erased")
	}
	delete(b.Materials, "broker-token")
	got = nil
	if publishPreparedNAS(b, func(string, string, []byte) error { got = append(got, "write"); return nil }) == nil || len(got) != 0 {
		t.Fatal("incomplete set has effects")
	}
}

func TestPrepareCLIHasNoPathsOrAuthorityOverrides(t *testing.T) {
	for _, args := range [][]string{{"prepare", "extra"}, {"prepare", "--plan", "arbitrary"}, {"prepare", "--out", "arbitrary"}, {"prepare", "--endpoint", "arbitrary"}, {"prepare", "--authority", "rsa"}} {
		out := new(bytes.Buffer)
		cmd := newScenarioCommand(bytes.NewReader(nil), out)
		cmd.SetArgs(args)
		if cmd.Execute() == nil || out.Len() != 0 {
			t.Fatal("arbitrary producer selector accepted")
		}
	}
}
