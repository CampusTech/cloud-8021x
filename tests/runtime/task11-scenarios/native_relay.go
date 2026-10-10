package main

import (
	"bytes"
	"errors"
	"net"

	sc "github.com/CampusTech/cloud-8021x/tests/runtime/task11-acceptance/scenariocontract"
)

type nativeRelay struct {
	plan      nasPrivatePlan
	secret    []byte
	client    *net.UDPAddr
	request   []byte
	exchanges int
	final     sc.EAPResult
	class     string
}

func (r *nativeRelay) forward(address *net.UDPAddr, packet []byte) (*net.UDPAddr, error) {
	if r == nil || address == nil || address.Port < 1 || address.Port > 65535 || r.exchanges >= 256 || r.final.Accepted || r.final.Rejected || validatePlan(r.plan.Scenario) != nil {
		return nil, errors.New("bounded fixed native relay required")
	}
	if address.IP.String() == "10.203.11.40" {
		if address.Port == 18120 || (r.client != nil && r.client.String() != address.String()) || validateNativeEAPRequest(packet, r.secret, r.plan) != nil {
			return nil, errors.New("native client changed or failed authentication")
		}
		if r.client == nil {
			copyAddress := *address
			copyAddress.IP = bytes.Clone(address.IP)
			r.client = &copyAddress
		}
		clear(r.request)
		r.request = bytes.Clone(packet)
		r.exchanges++
		return &net.UDPAddr{IP: net.ParseIP(r.plan.Scenario.Target), Port: 1812}, nil
	}
	if address.IP.String() != r.plan.Scenario.Target || address.Port != 1812 || r.client == nil || len(r.request) == 0 {
		return nil, errors.New("native reply from unmatched peer")
	}
	actual, class, e := validateNativeEAPResponse(packet, r.request, r.secret)
	if e != nil {
		return nil, e
	}
	r.exchanges++
	if actual.Accepted || actual.Rejected {
		r.final = actual
		r.class = class
	}
	return r.client, nil
}
