package main

import (
	"bytes"
	"crypto/md5" // RADIUS protocol authenticators are fixed MD5; not password hashing.
	"encoding/binary"
	"strings"
	"testing"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/accounting/binding"
)

func signedServerReply(t *testing.T, request []byte, secret []byte, code byte, attrs []byte) []byte {
	t.Helper()
	reply := make([]byte, 20+len(attrs))
	reply[0] = code
	reply[1] = request[1]
	binary.BigEndian.PutUint16(reply[2:4], uint16(len(reply)))
	copy(reply[4:20], request[4:20])
	copy(reply[20:], attrs)
	sum := md5.Sum(append(append([]byte(nil), reply...), secret...))
	copy(reply[4:20], sum[:])
	return reply
}
func attribute(t byte, value []byte) []byte { return append([]byte{t, byte(len(value) + 2)}, value...) }
func numericTunnel(t byte, n uint32) []byte {
	v := make([]byte, 4)
	binary.BigEndian.PutUint32(v, n)
	return attribute(t, v)
}

func TestActualWireAuthenticatorAndNumericVLAN(t *testing.T) {
	secret := []byte("task11-private-nas-secret")
	req := make([]byte, 20)
	req[0] = 1
	req[1] = 7
	binary.BigEndian.PutUint16(req[2:4], 20)
	copy(req[4:20], []byte("independentnonce"))
	attrs := append(numericTunnel(64, 13), numericTunnel(65, 6)...)
	attrs = append(attrs, attribute(81, []byte("120"))...)
	attrs = append(attrs, attribute(25, []byte("actual-server-class"))...)
	good := signedServerReply(t, req, secret, 2, attrs)
	if _, err := validateResponse(good, req, secret, 2); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func([]byte){func(v []byte) { v[4] ^= 1 }, func(v []byte) { v[1]++ }, func(v []byte) { v[3]-- }, func(v []byte) { v[0] = 3 }} {
		bad := bytes.Clone(good)
		mutate(bad)
		if _, err := validateResponse(bad, req, secret, 2); err == nil {
			t.Fatal("invalid response accepted")
		}
	}
	// A correctly authenticated string-valued type is still the wrong UniFi wire.
	badAttrs := append(attribute(64, []byte("VLAN")), numericTunnel(65, 6)...)
	badAttrs = append(badAttrs, attribute(81, []byte("120"))...)
	badAttrs = append(badAttrs, attribute(25, []byte("class"))...)
	if _, err := validateResponse(signedServerReply(t, req, secret, 2, badAttrs), req, secret, 2); err == nil {
		t.Fatal("string Tunnel-Type accepted")
	}
	duplicate := append(bytes.Clone(attrs), numericTunnel(64, 13)...)
	if _, err := validateResponse(signedServerReply(t, req, secret, 2, duplicate), req, secret, 2); err == nil {
		t.Fatal("duplicate tunnel type accepted")
	}
	if _, err := validateResponse(signedServerReply(t, req, secret, 3, nil), req, secret, 3); err != nil {
		t.Fatal("genuine reject refused", err)
	}
}

func actualClassForPureTest(t *testing.T, now time.Time) ([]byte, string) {
	t.Helper()
	key := []byte(strings.Repeat("k", 32))
	vlan := 120
	token, err := binding.IssueWithRandom(key, binding.Attribution{DeviceID: "fleet:1", Fingerprint: strings.Repeat("a", 64), VLAN: &vlan}, "task11", "AA:BB:CC:DD:EE:FF", now, bytes.NewReader(make([]byte, 12)))
	if err != nil {
		t.Fatal(err)
	}
	return key, token
}

func TestIndependentExpectationsZeroBaselinesAndCrossNodeDuplicates(t *testing.T) {
	now := time.Unix(1800000000, 0).UTC()
	key, token := actualClassForPureTest(t, now)
	p := fixturePlan()
	expected, err := deriveExpectations(p, "AA:BB:CC:DD:EE:FF", token, key, now, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(expected.Events) != 3 || len(expected.Intervals) != 2 || expected.Upload != 1600 || expected.Download != 2900 || expected.Seconds != 90 {
		t.Fatalf("incorrect independent new-session deltas: %+v", expected)
	}
	p.Events = append(p.Events, p.Events[1], p.Events[2])
	repeated, err := deriveExpectations(p, "AA:BB:CC:DD:EE:FF", token, key, now, now)
	if err != nil || len(repeated.Events) != 3 || len(repeated.Intervals) != 2 || repeated.Upload != 1600 || repeated.Download != 2900 {
		t.Fatalf("cross-node duplicates credited: %+v %v", repeated, err)
	}
	p = fixturePlan()
	p.Scenario = "ongoing-baseline"
	p.Case = "ongoing-interim"
	p.Events = p.Events[1:]
	ongoing, err := deriveExpectations(p, "AA:BB:CC:DD:EE:FF", token, key, now, now)
	if err != nil || len(ongoing.Intervals) != 1 || ongoing.Upload != 600 || ongoing.Download != 900 || ongoing.Seconds != 30 {
		t.Fatalf("ongoing first interim credited old traffic: %+v %v", ongoing, err)
	}
	p.Events = p.Events[1:]
	p.Case = "ongoing-stop"
	stopped, err := deriveExpectations(p, "AA:BB:CC:DD:EE:FF", token, key, now, now)
	if err != nil || len(stopped.Intervals) != 0 || stopped.Upload != 0 {
		t.Fatalf("first stop credited old traffic: %+v %v", stopped, err)
	}
	for _, station := range []string{"00:11:22:33:44:55", "invalid"} {
		if _, err := deriveExpectations(fixturePlan(), station, token, key, now, now); err == nil {
			t.Fatal("foreign or invalid Class context accepted")
		}
	}
	if _, err := deriveExpectations(fixturePlan(), "AA:BB:CC:DD:EE:FF", token, key, now.Add(31*24*time.Hour), now); err == nil {
		t.Fatal("expired Class accepted")
	}
}
