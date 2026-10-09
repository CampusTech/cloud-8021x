package main

import (
	"encoding/json"
	"errors"
	"slices"

	"github.com/CampusTech/cloud-8021x/internal/adoption"

	"github.com/CampusTech/cloud-8021x/tests/runtime/task11-acceptance/scenariocontract"
)

const maxScenarioNodeInput = 128 << 10

type scenarioNodeInput struct {
	Schema       int    `json:"schema"`
	RequestBytes []byte `json:"request_bytes"`
	ConfigSHA256 string `json:"config_sha256"`
	Selection    []byte `json:"selection_bytes,omitempty"`
}

// This local pipe binds the selected reader to the exact enrolled node/config.
// The controller must first authenticate actual protected prior issuance. These
// bytes select only the two fixed read-only readers, never a path, SQL or DSN.
func decodeScenarioNodeInput(raw []byte, operation, hostname, applicationSHA, configSHA string) (scenariocontract.Request, []byte, error) {
	var in scenarioNodeInput
	var fields map[string]json.RawMessage
	refuse := func() (scenariocontract.Request, []byte, error) {
		return scenariocontract.Request{}, nil, errors.New("exact closed scenario reader input required")
	}
	if len(raw) > maxScenarioNodeInput || decodeExactJSON(raw, &in) != nil || decodeExactJSON(raw, &fields) != nil || in.Schema != 1 || !validSHA(applicationSHA) || !validSHA(configSHA) || in.ConfigSHA256 != configSHA {
		return refuse()
	}
	expected := map[string]bool{"schema": true, "request_bytes": true, "config_sha256": true}
	if operation == "scenario-ca" {
		expected["selection_bytes"] = true
	} else if operation != "scenario-accounting" {
		return refuse()
	}
	if len(fields) != len(expected) {
		return refuse()
	}
	for key := range expected {
		if _, ok := fields[key]; !ok {
			return refuse()
		}
	}
	r, err := scenariocontract.DecodeRequest(in.RequestBytes)
	if err != nil || r.ApplicationSHA256 != applicationSHA || !slices.Contains([]string{"task11-blue-primary", "task11-blue-secondary", "task11-green-primary", "task11-green-secondary"}, hostname) {
		return refuse()
	}
	if operation == "scenario-accounting" {
		if r.Action != "read-accounting" || hostname != "task11-"+r.Node || len(in.Selection) != 0 {
			return refuse()
		}
		return r, nil, nil
	}
	if r.Action != "read-ca-issued" || len(in.Selection) == 0 || len(in.Selection) > 2048 || adoption.Digest(in.Selection) != r.SelectionSHA256 {
		return refuse()
	}
	selection, err := scenariocontract.DecodeCASelection(in.Selection)
	if err != nil || selection.AttemptID != r.AttemptID || selection.IssuanceSequence != r.IssuanceSequence {
		return refuse()
	}
	return r, in.Selection, nil
}
