package main

import (
	"bytes"
	"errors"
	"strings"

	"github.com/CampusTech/cloud-8021x/internal/accounting"
)

// The only live executable is the measured installed /usr/bin/eapol_test;
// arguments use fixed NAS paths/address and immutable independently chosen MAC.
// The secret is private; callers must never log argv or child TLS diagnostics.
func fixedEAPArguments(p nasPrivatePlan, secret []byte) ([]string, error) {
	if e := validatePlan(p.Scenario); e != nil {
		return nil, e
	}
	if len(secret) < 8 || len(secret) > 253 || !bytes.HasPrefix(secret, []byte("task11-")) || strings.ContainsAny(string(secret), "\x00\r\n") || !shaPattern.MatchString(p.Materials["radius-secret"]) || digestBytes(secret) != p.Materials["radius-secret"] {
		return nil, errors.New("pinned synthetic private RADIUS credential required")
	}
	one := func(v string) accounting.Attribute { return accounting.Attribute{Value: v, Count: 1} }
	if _, e := accounting.CanonicalKey(accounting.Raw{SourceIP: p.Scenario.NAS, NASIP: one(p.Scenario.NAS), Station: one(p.Station), Session: one(p.Scenario.Session)}); e != nil {
		return nil, errors.New("independently chosen canonical station required")
	}
	profile := "eap.conf"
	if p.Scenario.Case == "eap-unenrolled" {
		profile = "reject-eap.conf"
	}
	return []string{"-c", nasMaterialRoot + "/" + profile, "-a", "10.203.11.40", "-A", "10.203.11.40", "-p", "18120", "-s", string(secret), "-M", p.Station, "-t", "15", "-N", "61:d:19"}, nil
}
