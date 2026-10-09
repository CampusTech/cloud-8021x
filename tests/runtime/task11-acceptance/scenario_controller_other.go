//go:build !linux

package main

import (
	"context"

	sc "github.com/CampusTech/cloud-8021x/tests/runtime/task11-acceptance/scenariocontract"
)

func executeScenarioStage(context.Context, sc.Stage) error { return errScenarioController }
