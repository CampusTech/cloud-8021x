package main

import (
	"errors"
	"io"
	"time"

	sc "github.com/CampusTech/cloud-8021x/tests/runtime/task11-acceptance/scenariocontract"
)

type nativeTransmission struct {
	peer   string
	event  plannedEvent
	packet []byte
}
type nativeAccounting struct {
	result        sc.NASResult
	transmissions []nativeTransmission
}

// All expected IDs are derived from the actual verified Class before any send.
func prepareNativeAccounting(p nasPrivatePlan, actual sc.EAPResult, class string, key, secret []byte, received time.Time, entropy io.Reader) (nativeAccounting, error) {
	var out nativeAccounting
	if entropy == nil || !actual.Accepted || actual.Rejected || actual.ResponseCode != 2 || !shaPattern.MatchString(actual.ResponseAuthenticatorSHA256) || actual.TunnelType != 13 || actual.TunnelMediumType != 6 || actual.VLAN != 120 || received.IsZero() {
		return out, errors.New("actual accepted native exchange required")
	}
	if _, e := fixedEAPArguments(p, secret); e != nil {
		return out, e
	}
	expected, e := deriveNASExpectations(p, class, key, received, p.Scenario.CollectionEpoch)
	if e != nil {
		return out, e
	}
	if len(expected.Events) == 0 || expected.Events[0].Identity == nil {
		return out, errors.New("actual Class attribution absent")
	}
	out.result = sc.NASResult{Peer: p.Scenario.Target, Session: p.Scenario.Session, Station: p.Station, ChosenAt: received.UTC(), ClassSHA256: digestBytes([]byte(class)), Attribution: *expected.Events[0].Identity, EAP: actual}
	for _, v := range expected.Events {
		out.result.Expected.EventIDs = append(out.result.Expected.EventIDs, v.ID)
	}
	for _, v := range expected.Intervals {
		out.result.Expected.UsageIDs = append(out.result.Expected.UsageIDs, v.ID)
	}
	out.result.Expected.UploadBytes = expected.Upload
	out.result.Expected.DownloadBytes = expected.Download
	out.result.Expected.Seconds = expected.Seconds
	peers := []string{p.Scenario.Target}
	if p.Scenario.Scenario == "duplicate-pair" {
		peers = []string{"10.203.11.21", "10.203.11.22"}
	}
	if len(p.Scenario.Events)*len(peers) > 16 {
		return nativeAccounting{}, errors.New("bounded native transmission set exceeded")
	}
	for _, v := range p.Scenario.Events {
		var id [1]byte
		if _, e = io.ReadFull(entropy, id[:]); e != nil {
			return nativeAccounting{}, errors.New("native packet identity entropy unavailable")
		}
		packet, e := makeAccountingRequest(p.Scenario, v, p.Station, class, secret, id[0])
		if e != nil {
			return nativeAccounting{}, e
		}
		for _, peer := range peers {
			out.transmissions = append(out.transmissions, nativeTransmission{peer: peer, event: v, packet: append([]byte(nil), packet...)})
		}
	}
	return out, nil
}
