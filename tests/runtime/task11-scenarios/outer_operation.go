package main

import (
	"context"
	"encoding/json"
	"errors"

	sc "github.com/CampusTech/cloud-8021x/tests/runtime/task11-acceptance/scenariocontract"
)

type controllerRoute interface {
	publishRequest(sc.Request, []byte) error
	dispatch(context.Context, sc.Stage) error
	readResult(context.Context, sc.Request) ([]byte, error)
}

func submitOperation(ctx context.Context, route controllerRoute, request sc.Request) (sc.Result, []byte, error) {
	if ctx == nil || ctx.Err() != nil || route == nil || request.Validate() != nil {
		return sc.Result{}, nil, errors.New("valid bounded controller operation required")
	}
	raw, err := json.Marshal(request)
	if err != nil || len(raw) > sc.MaxRequestBytes {
		return sc.Result{}, nil, errors.New("bounded controller request unavailable")
	}
	pin := digestBytes(raw)
	if err = route.publishRequest(request, raw); err != nil {
		return sc.Result{}, nil, err
	}
	stage := sc.Stage{Stage: "scenario-operation", AttemptID: request.AttemptID, Sequence: request.Sequence, RequestSHA256: pin}
	if err = route.dispatch(ctx, stage); err != nil {
		return sc.Result{}, nil, err
	}
	observed, err := route.readResult(ctx, request)
	if err != nil {
		return sc.Result{}, nil, err
	}
	result, err := sc.DecodeResult(observed, request, pin)
	if err != nil {
		return sc.Result{}, nil, errors.New("genuine retired controller result differs")
	}
	return result, observed, nil
}
