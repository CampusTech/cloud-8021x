package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5" // RFC3579 mandates HMAC-MD5; this is not a password hash.
	"encoding/binary"
	"testing"
)

func pureEAPRequest(p nasPrivatePlan, secret []byte) []byte {
	packet := make([]byte, 20)
	packet[0], packet[1] = 1, 7
	copy(packet[4:20], []byte("independentnonce"))
	packet = append(packet, attribute(4, []byte{10, 203, 11, 40})...)
	packet = append(packet, attribute(31, []byte(p.Station))...)
	packet = append(packet, attribute(79, []byte{2, 1, 0, 5, 1})...)
	packet = append(packet, attribute(80, make([]byte, 16))...)
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	mac := hmac.New(md5.New, secret)
	_, _ = mac.Write(packet)
	copy(packet[len(packet)-16:], mac.Sum(nil))
	return packet
}
func pureEAPReply(t *testing.T, request, secret []byte, code byte, attrs []byte) []byte {
	t.Helper()
	attrs = append(bytes.Clone(attrs), attribute(80, make([]byte, 16))...)
	reply := make([]byte, 20+len(attrs))
	reply[0], reply[1] = code, request[1]
	binary.BigEndian.PutUint16(reply[2:4], uint16(len(reply)))
	copy(reply[4:20], request[4:20])
	copy(reply[20:], attrs)
	mac := hmac.New(md5.New, secret)
	_, _ = mac.Write(reply)
	copy(reply[len(reply)-16:], mac.Sum(nil))
	return signedServerReply(t, request, secret, code, reply[20:])
}
func TestNativeClientRequestBindsNASStationAndMessageAuthenticator(t *testing.T) {
	p := pureNASPlan()
	secret := []byte("task11-private-nas-secret")
	good := pureEAPRequest(p, secret)
	before := bytes.Clone(good)
	if e := validateNativeEAPRequest(good, secret, p); e != nil {
		t.Fatal(e)
	}
	if !bytes.Equal(good, before) {
		t.Fatal("native request rewritten")
	}
	for _, kind := range []string{"station", "NAS", "HMAC", "length", "code", "duplicate"} {
		t.Run(kind, func(t *testing.T) {
			bad := bytes.Clone(good)
			switch kind {
			case "station":
				plan := p
				plan.Station = "00:11:22:33:44:55"
				bad = pureEAPRequest(plan, secret)
			case "NAS":
				bad[25] ^= 1
			case "HMAC":
				bad[len(bad)-1] ^= 1
			case "length":
				bad[3]--
			case "code":
				bad[0] = 4
			case "duplicate":
				bad = append(bad, attribute(31, []byte(p.Station))...)
				binary.BigEndian.PutUint16(bad[2:4], uint16(len(bad)))
			}
			if validateNativeEAPRequest(bad, secret, p) == nil {
				t.Fatal("foreign/unauthenticated native input accepted")
			}
		})
	}
	// Canonical formatting may vary in genuine eapol_test; preserve wire bytes.
	alternate := p
	alternate.Station = "aa-bb-cc-dd-ee-ff"
	if e := validateNativeEAPRequest(pureEAPRequest(alternate, secret), secret, p); e != nil {
		t.Fatal("canonical equivalent native station refused", e)
	}
}
func TestNativeResponseRequiresBothAuthenticatorsAndExactAdmission(t *testing.T) {
	p := pureNASPlan()
	secret := []byte("task11-private-nas-secret")
	request := pureEAPRequest(p, secret)
	attrs := append(numericTunnel(64, 13), numericTunnel(65, 6)...)
	attrs = append(attrs, attribute(81, []byte("120"))...)
	attrs = append(attrs, attribute(25, []byte("private-class"))...)
	attrs = append(attrs, attribute(79, []byte{3, 1, 0, 4})...)
	good := pureEAPReply(t, request, secret, 2, attrs)
	actual, class, e := validateNativeEAPResponse(good, request, secret)
	if e != nil || !actual.Accepted || actual.Rejected || actual.TunnelType != 13 || actual.TunnelMediumType != 6 || actual.VLAN != 120 || class != "private-class" || actual.ResponseAuthenticatorSHA256 != digestBytes(good[4:20]) {
		t.Fatal("authenticated admission absent", e)
	}
	// Correct response MD5 alone must never permit a bad Message-Authenticator.
	badAttrs := append(bytes.Clone(attrs), attribute(80, make([]byte, 16))...)
	bad := signedServerReply(t, request, secret, 2, badAttrs)
	if _, _, e = validateNativeEAPResponse(bad, request, secret); e == nil {
		t.Fatal("MD5-only EAP reply accepted")
	}
	for _, code := range []byte{3, 11} {
		eap := []byte{4, 1, 0, 4}
		if code == 11 {
			eap = []byte{1, 2, 0, 5, 13}
		}
		reply := pureEAPReply(t, request, secret, code, attribute(79, eap))
		actual, class, e = validateNativeEAPResponse(reply, request, secret)
		if e != nil || actual.ResponseCode != int(code) || actual.Accepted || class != "" || actual.Rejected != (code == 3) {
			t.Fatal("genuine reject/challenge observation changed", e)
		}
	}
	missing := signedServerReply(t, request, secret, 3, nil)
	if _, _, e = validateNativeEAPResponse(missing, request, secret); e == nil {
		t.Fatal("missing native HMAC accepted")
	}
}
