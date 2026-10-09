//go:build linux

package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"

	"github.com/CampusTech/cloud-8021x/tests/runtime/task11-acceptance/scenariocontract"
)

// Only the fixed namespace transport can reach this handler. Each actual reader
// reopens the protected configuration/credentials and reserves its one writer
// connection. Outer nodeCall independently rechecks registration and retires the
// operation cgroup before its caller can publish a completion record.
func nodeScenarioRead(ctx context.Context, operation string, input io.Reader, output io.Writer) error {
	raw, err := boundedInput(input, maxScenarioNodeInput)
	if err != nil {
		return errors.New("bounded private scenario reader input unavailable")
	}
	defer clear(raw)
	_, manifest, err := nodeConfig()
	if err != nil {
		return errors.New("protected scenario reader configuration unavailable")
	}
	proof, err := localProof()
	if err != nil || proof.ConfigSHA256 != manifest.ConfigSHA256 || proof.ApplicationSHA256 != manifest.ApplicationSHA256 {
		return errors.New("actual enrolled scenario reader identity differs")
	}
	r, selection, err := decodeScenarioNodeInput(raw, operation, proof.Hostname, manifest.ApplicationSHA256, manifest.ConfigSHA256)
	if err != nil {
		return err
	}
	defer clear(selection)
	var observed any
	switch operation {
	case "scenario-accounting":
		var value scenariocontract.LedgerObservation
		value, err = observeScenarioAccounting(ctx, r.Sessions)
		observed = value
	case "scenario-ca":
		var value scenariocontract.CAObservation
		value, err = observeScenarioCA(ctx, selection)
		observed = value
	default:
		return errors.New("unknown closed scenario reader")
	}
	if err != nil {
		return errors.New("actual selected read-only scenario snapshot unavailable")
	}
	// []byte payload/receipt/row fields stay opaque through standard base64 JSON;
	// no typed-map reconstruction or raw business JSON normalization occurs.
	return json.NewEncoder(output).Encode(observed)
}
