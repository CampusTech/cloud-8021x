//go:build !linux

package main

import (
	"context"
	"errors"

	"github.com/CampusTech/cloud-8021x/tests/runtime/task11-passive-audit/contract"
)

func observe(context.Context, contract.Request, string) (contract.Result, error) {
	return contract.Result{}, errors.New("enrolled Linux node required")
}
