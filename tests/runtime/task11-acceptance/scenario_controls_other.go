//go:build !linux

package main

import (
	"context"
	"io"
)

func scenarioControl(ctx context.Context, e enrollment, requestRaw []byte) (scenarioControlObservation, error) {
	return scenarioControlObservation{}, errScenarioControl
}
func nodeScenarioProbe(ctx context.Context, in io.Reader, out io.Writer) error {
	return errScenarioControl
}
func scenarioCleanupEntry(ctx context.Context, args []string, out io.Writer) error {
	return errScenarioControl
}
