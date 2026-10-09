package main

import (
	"errors"
	"strconv"
	"strings"

	"github.com/CampusTech/cloud-8021x/internal/adoption"
)

type recoveryRequest struct {
	Kind, Guard, Work, PayloadSHA256, RequestID, ApplicationSHA256 string
	Generation                                                     int64
	ExecutionID                                                    string
}

func recoveryCommand(r recoveryRequest) ([]string, error) {
	if r.ExecutionID != "" && !executionIdentity.MatchString(r.ExecutionID) {
		return nil, errors.New("bounded single execution identity required")
	}
	if !validSHA(r.ApplicationSHA256) {
		return nil, errors.New("exact shipping release pin required")
	}
	argv := []string{"/usr/local/bin/cloud-8021x", "--config", "/etc/cloud-8021x/config.yaml", "state"}
	switch r.Kind {
	case "retained-legacy":
		if !validSHA(r.Guard) || r.Work != "" || r.Generation != 0 || r.PayloadSHA256 != "" || r.RequestID != "" || r.ExecutionID != "" {
			return nil, errors.New("exact original legacy guard required")
		}
		return append(argv, "recover-collection", "--guard", r.Guard), nil
	case "green-work":
		if r.Guard != "" || !strings.HasPrefix(r.Work, "fleet-cert:") || len(r.Work) > 512 || r.Generation < 1 || !validSHA(r.PayloadSHA256) || !validSHA(r.RequestID) {
			return nil, errors.New("exact original Fleet work required")
		}
		argv = append(argv, "recover-work", "--kind", "fleet-terminal", "--work", r.Work, "--generation", strconv.FormatInt(r.Generation, 10), "--payload-sha256", r.PayloadSHA256, "--request", r.RequestID)
		if r.ExecutionID != "" {
			argv = append(argv, "--execution-id", r.ExecutionID)
		}
		return argv, nil
	}
	return nil, errors.New("only GET-only certificate result recovery is allowed")
}

func workRecoveryRequest(w durableWork, app string) recoveryRequest {
	r := recoveryRequest{Kind: "green-work", ApplicationSHA256: app, Work: w.ID, Generation: w.Generation, PayloadSHA256: adoption.Digest(w.Payload)}
	r.RequestID = adoption.Digest([]byte("task11-get-only:" + w.ID + ":" + r.PayloadSHA256))
	return r
}
