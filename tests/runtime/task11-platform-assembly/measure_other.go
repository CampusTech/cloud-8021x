//go:build !linux

package main

import (
	"context"
	"errors"
)

func measureBaseLoops(context.Context) ([]baseLoopFact, error) {
	return nil, errors.New("actual Linux kernel loop observations required")
}
