//go:build !linux

package main

import (
	"context"
	"errors"

	"github.com/CampusTech/cloud-8021x/tests/runtime/task11-acceptance/scenariocontract"
)

func observeScenarioAccounting(context.Context, []string) (scenariocontract.LedgerObservation, error) {
	return scenariocontract.LedgerObservation{}, errors.New("actual scenario SQL observation requires Linux")
}
func observeScenarioCA(context.Context, []byte) (scenariocontract.CAObservation, error) {
	return scenariocontract.CAObservation{}, errors.New("actual scenario CA observation requires Linux")
}
