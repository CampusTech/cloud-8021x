package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/CampusTech/cloud-8021x/internal/adoption"
	"github.com/CampusTech/cloud-8021x/tests/runtime/task11-acceptance/scenariocontract"
)

func scenarioReaderFixture(t *testing.T, ca bool) (scenarioNodeInput, scenariocontract.Request, []byte) {
	t.Helper()
	pin := strings.Repeat("a", 64)
	r := scenariocontract.Request{Schema: 1, AttemptID: "task11-" + strings.Repeat("b", 32), Sequence: 2, Action: "read-accounting", Pins: scenariocontract.Pins{PlanSHA256: pin, PlatformSHA256: pin, EnrollmentSHA256: pin, ApplicationSHA256: pin, ScenarioSHA256: pin}, Node: "green-primary", Sessions: []string{"task11-selected"}}
	in := scenarioNodeInput{Schema: 1, ConfigSHA256: strings.Repeat("c", 64)}
	if ca {
		r.Action, r.Node, r.Sessions, r.IssuanceSequence = "read-ca-issued", "", nil, 1
		s := scenariocontract.CASelection{Schema: 1, AttemptID: r.AttemptID, IssuanceSequence: 1, ResultSHA256: pin, Authority: "rsa", Serial: "123", LeafDERSHA256: pin, OriginalRootSHA256: pin, OriginalIntermediateSHA256: pin}
		var err error
		in.Selection, err = json.Marshal(s)
		if err != nil {
			t.Fatal(err)
		}
		in.Selection = append(append([]byte(" \n"), in.Selection...), '\n')
		r.SelectionSHA256 = adoption.Digest(in.Selection)
	}
	var err error
	in.RequestBytes, err = json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	in.RequestBytes = append(append([]byte(" \n"), in.RequestBytes...), '\n')
	raw, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	return in, r, raw
}

func TestScenarioReaderAcceptsExactSelectedNodeAndRawCASelection(t *testing.T) {
	for _, ca := range []bool{false, true} {
		in, want, raw := scenarioReaderFixture(t, ca)
		op := "scenario-accounting"
		if ca {
			op = "scenario-ca"
		}
		got, selection, err := decodeScenarioNodeInput(raw, op, "task11-green-primary", want.ApplicationSHA256, in.ConfigSHA256)
		if err != nil || got.Action != want.Action || got.AttemptID != want.AttemptID || !bytes.Equal(selection, in.Selection) {
			t.Fatalf("exact selected reader and raw selection refused: %v", err)
		}
		if ca {
			for _, node := range []string{"blue-primary", "blue-secondary", "green-primary", "green-secondary"} {
				if _, _, err := decodeScenarioNodeInput(raw, op, "task11-"+node, want.ApplicationSHA256, in.ConfigSHA256); err != nil {
					t.Fatal("fixed original/adopted CA node refused", err)
				}
			}
		}
	}
}

func TestScenarioReaderRejectsSubstitutionBeforeSQL(t *testing.T) {
	for _, ca := range []bool{false, true} {
		in, r, raw := scenarioReaderFixture(t, ca)
		op := "scenario-accounting"
		if ca {
			op = "scenario-ca"
		}
		for _, tc := range []struct{ operation, hostname, app, config string }{
			{"arbitrary-query", "task11-green-primary", r.ApplicationSHA256, in.ConfigSHA256},
			{op, "production-primary", r.ApplicationSHA256, in.ConfigSHA256},
			{op, "task11-green-primary", strings.Repeat("d", 64), in.ConfigSHA256},
			{op, "task11-green-primary", r.ApplicationSHA256, strings.Repeat("d", 64)},
			{op, "task11-green-primary", "", in.ConfigSHA256},
		} {
			if _, _, err := decodeScenarioNodeInput(raw, tc.operation, tc.hostname, tc.app, tc.config); err == nil {
				t.Fatal("foreign operation/node/app/config reached reader")
			}
		}
		if !ca {
			for _, node := range []string{"task11-green-secondary", "task11-blue-primary", "task11-blue-secondary"} {
				if _, _, err := decodeScenarioNodeInput(raw, op, node, r.ApplicationSHA256, in.ConfigSHA256); err == nil {
					t.Fatal("unselected accounting node reached reader")
				}
			}
		}
		other := "scenario-ca"
		if ca {
			other = "scenario-accounting"
		}
		if _, _, err := decodeScenarioNodeInput(raw, other, "task11-green-primary", r.ApplicationSHA256, in.ConfigSHA256); err == nil {
			t.Fatal("other reader action accepted")
		}
	}
}

func TestScenarioReaderRejectsRawInputAliasesAndBounds(t *testing.T) {
	for _, ca := range []bool{false, true} {
		in, r, raw := scenarioReaderFixture(t, ca)
		op := "scenario-accounting"
		if ca {
			op = "scenario-ca"
		}
		check := func(raw []byte) {
			t.Helper()
			if _, _, err := decodeScenarioNodeInput(raw, op, "task11-green-primary", r.ApplicationSHA256, in.ConfigSHA256); err == nil {
				t.Fatal("invalid or irrelevant private reader input accepted")
			}
		}
		for _, field := range []string{"schema", "request_bytes", "config_sha256"} {
			check(bytes.Replace(raw, []byte(`"`+field+`"`), []byte(`"`+strings.ToUpper(field)+`"`), 1))
		}
		check(append(append([]byte(nil), raw...), []byte(" {}")...))
		check([]byte(`{"schema":1,"schema":1}`))
		check(bytes.Replace(raw, []byte(`"schema":1`), []byte(`"schema":1,"path":"/etc/passwd"`), 1))
		check(bytes.Repeat([]byte(" "), maxScenarioNodeInput+1))
		in.Schema = 2
		bad, _ := json.Marshal(in)
		check(bad)
		in.Schema = 1
		in.RequestBytes = bytes.Repeat([]byte(" "), scenariocontract.MaxRequestBytes+1)
		bad, _ = json.Marshal(in)
		check(bad)
		_, _, raw = scenarioReaderFixture(t, ca)
		if !ca {
			check(bytes.Replace(raw, []byte(`"schema":1`), []byte(`"schema":1,"selection_bytes":null`), 1))
			check(bytes.Replace(raw, []byte(`"schema":1`), []byte(`"schema":1,"selection_bytes":""`), 1))
		}
	}
}

func TestScenarioReaderAuthenticatesExactSelectionBytesAndCoordinates(t *testing.T) {
	in, r, _ := scenarioReaderFixture(t, true)
	original := append([]byte(nil), in.Selection...)
	for _, mutate := range []func(*scenarioNodeInput){
		func(v *scenarioNodeInput) { v.Selection = append(v.Selection, '\n') },
		func(v *scenarioNodeInput) { v.Selection = nil },
		func(v *scenarioNodeInput) { v.Selection = bytes.Repeat([]byte(" "), 2049) },
		func(v *scenarioNodeInput) {
			s, err := scenariocontract.DecodeCASelection(v.Selection)
			if err != nil {
				t.Fatal(err)
			}
			s.AttemptID = "task11-" + strings.Repeat("d", 32)
			v.Selection, _ = json.Marshal(s)
			r.SelectionSHA256 = adoption.Digest(v.Selection)
			v.RequestBytes, _ = json.Marshal(r)
		},
		func(v *scenarioNodeInput) {
			s, err := scenariocontract.DecodeCASelection(v.Selection)
			if err != nil {
				t.Fatal(err)
			}
			s.IssuanceSequence = 2
			v.Selection, _ = json.Marshal(s)
			r.SelectionSHA256 = adoption.Digest(v.Selection)
			v.RequestBytes, _ = json.Marshal(r)
		},
	} {
		v := in
		v.Selection = append([]byte(nil), original...)
		mutate(&v)
		raw, _ := json.Marshal(v)
		if _, _, err := decodeScenarioNodeInput(raw, "scenario-ca", "task11-green-primary", r.ApplicationSHA256, in.ConfigSHA256); err == nil {
			t.Fatal("substituted selection hash or coordinates reached reader")
		}
	}
}
