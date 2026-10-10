package main

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/accounting/binding"
	sc "github.com/CampusTech/cloud-8021x/tests/runtime/task11-acceptance/scenariocontract"
)

func TestNativePreparationFreezesActualClassIDsBeforeTransmission(t *testing.T) {
	now := time.Unix(1800000000, 0).UTC()
	key, class := actualClassForPureTest(t, now)
	p := pureNASPlan()
	secret := []byte("task11-private-nas-secret")
	p.Materials["class-key"] = digestBytes(key)
	p.Materials["radius-secret"] = digestBytes(secret)
	actual := sc.EAPResult{Accepted: true, ResponseCode: 2, ResponseAuthenticatorSHA256: strings.Repeat("e", 64), TunnelType: 13, TunnelMediumType: 6, VLAN: 120}
	prepared, e := prepareNativeAccounting(p, actual, class, key, secret, now, bytes.NewReader([]byte{7, 8, 9}))
	if e != nil {
		t.Fatal(e)
	}
	result := prepared.result
	if result.ClassSHA256 != digestBytes([]byte(class)) || result.Attribution.Fingerprint != p.ClientLeafSHA256 || len(result.Expected.EventIDs) != 3 || len(result.Expected.UsageIDs) != 2 || result.Expected.UploadBytes != 1600 || result.Expected.DownloadBytes != 2900 || result.Expected.Seconds != 90 || len(prepared.transmissions) != 3 || len(result.Packets) != 0 {
		t.Fatal("expected IDs/counters not independently frozen before actual packet effects")
	}
	for i, v := range prepared.transmissions {
		if v.peer != p.Scenario.Target || v.event != p.Scenario.Events[i] || v.packet[0] != 4 || v.packet[1] != byte(7+i) || int(binary.BigEndian.Uint16(v.packet[2:4])) != len(v.packet) {
			t.Fatal("transmission changed planned native event")
		}
	}
	identity := binding.Verify(key, []string{class}, "task11", []string{p.Station}, now, binding.MaxAge)
	if identity == nil || result.Attribution.DeviceID != identity.DeviceID {
		t.Fatal("server Class attribution not actually verified")
	}
	for _, bad := range []string{"client", "secret", "reject", "entropy"} {
		t.Run(bad, func(t *testing.T) {
			plan := p
			plan.Materials = map[string]string{}
			for k, v := range p.Materials {
				plan.Materials[k] = v
			}
			response := actual
			random := []byte{7, 8, 9}
			switch bad {
			case "client":
				plan.ClientLeafSHA256 = strings.Repeat("b", 64)
			case "secret":
				plan.Materials["radius-secret"] = strings.Repeat("f", 64)
			case "reject":
				response.Accepted = false
				response.Rejected = true
				response.ResponseCode = 3
			case "entropy":
				random = nil
			}
			if _, e := prepareNativeAccounting(plan, response, class, key, secret, now, bytes.NewReader(random)); e == nil {
				t.Fatal("unsafe accounting preparation accepted")
			}
		})
	}
}
func TestNativeDuplicatePairPreservesExactPacketsAcrossPeers(t *testing.T) {
	now := time.Unix(1800000000, 0).UTC()
	key, class := actualClassForPureTest(t, now)
	p := pureNASPlan()
	p.Scenario.Scenario = "duplicate-pair"
	p.Scenario.Case = "duplicate-pair"
	secret := []byte("task11-private-nas-secret")
	p.Materials["class-key"] = digestBytes(key)
	p.Materials["radius-secret"] = digestBytes(secret)
	actual := sc.EAPResult{Accepted: true, ResponseCode: 2, ResponseAuthenticatorSHA256: strings.Repeat("e", 64), TunnelType: 13, TunnelMediumType: 6, VLAN: 120}
	prepared, e := prepareNativeAccounting(p, actual, class, key, secret, now, bytes.NewReader([]byte{7, 8, 9}))
	if e != nil || len(prepared.transmissions) != 6 || len(prepared.result.Expected.EventIDs) != 3 || prepared.result.Expected.UploadBytes != 1600 {
		t.Fatal("cross-peer duplicate preparation absent", e)
	}
	for i := 0; i < 6; i += 2 {
		a, b := prepared.transmissions[i], prepared.transmissions[i+1]
		if a.peer != "10.203.11.21" || b.peer != "10.203.11.22" || !bytes.Equal(a.packet, b.packet) || a.event != b.event {
			t.Fatal("duplicate pair changed request identity/authenticator/counters")
		}
	}
}
