package main

import (
	"crypto/tls"
	"errors"
	"net/http"
)

// A closed phase mapping supplements the strict original-blue constructor;
// phase never replaces preserved authority/trust/provisioner inputs.
func phaseCAPeer(original, phase string) (string, error) {
	if original != "10.203.11.31" && original != "10.203.11.32" {
		return "", errors.New("closed original blue CA peer required")
	}
	switch phase {
	case "original":
		return original, nil
	case "adopted", "passive":
		if original == "10.203.11.31" {
			return "10.203.11.21", nil
		}
		return "10.203.11.22", nil
	default:
		return "", errors.New("unknown CA phase")
	}
}
func pinnedPhaseRSAClient(p caClientPlan, phase string, root, broker []byte, isBroker bool, pair *tls.Certificate) (*http.Client, error) {
	return rsaClientForPhase(p, phase, root, broker, isBroker, pair)
}
