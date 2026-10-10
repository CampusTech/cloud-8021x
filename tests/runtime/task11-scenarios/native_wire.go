package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5" // #nosec G501 -- RFC3579 mandates HMAC-MD5 for EAP RADIUS.
	"encoding/binary"
	"errors"

	"github.com/CampusTech/cloud-8021x/internal/accounting"
	sc "github.com/CampusTech/cloud-8021x/tests/runtime/task11-acceptance/scenariocontract"
)

func nativeEAPAttributes(packet []byte) (map[byte][][]byte, error) {
	if len(packet) < 20 || len(packet) > 4096 || int(binary.BigEndian.Uint16(packet[2:4])) != len(packet) {
		return nil, errors.New("bounded exact native packet required")
	}
	attrs, e := parseAttributes(packet[20:])
	if e != nil {
		return nil, e
	}
	eap := bytes.Join(attrs[79], nil)
	if len(eap) < 4 || int(binary.BigEndian.Uint16(eap[2:4])) != len(eap) {
		return nil, errors.New("native EAP message framing differs")
	}
	if len(attrs[80]) != 1 || len(attrs[80][0]) != 16 {
		return nil, errors.New("single native Message-Authenticator required")
	}
	return attrs, nil
}
func verifyNativeHMAC(packet, request, secret []byte) error {
	if len(secret) < 8 || len(secret) > 253 {
		return errors.New("bounded native secret required")
	}
	authenticated := bytes.Clone(packet)
	defer clear(authenticated)
	if request != nil {
		if len(request) < 20 {
			return errors.New("matching native request required")
		}
		copy(authenticated[4:20], request[4:20])
	}
	var expected []byte
	for at := 20; at < len(authenticated); at += int(authenticated[at+1]) {
		if authenticated[at] == 80 {
			expected = bytes.Clone(authenticated[at+2 : at+18])
			clear(authenticated[at+2 : at+18])
		}
	}
	mac := hmac.New(md5.New, secret)
	_, _ = mac.Write(authenticated)
	if !hmac.Equal(expected, mac.Sum(nil)) {
		return errors.New("native Message-Authenticator mismatch")
	}
	return nil
}
func validateNativeEAPRequest(packet, secret []byte, p nasPrivatePlan) error {
	attrs, e := nativeEAPAttributes(packet)
	if e != nil {
		return e
	}
	if packet[0] != 1 || bytes.Join(attrs[79], nil)[0] != 2 || len(attrs[4]) != 1 || !bytes.Equal(attrs[4][0], []byte{10, 203, 11, 40}) || len(attrs[31]) != 1 {
		return errors.New("fixed native request identity required")
	}
	one := func(v string) accounting.Attribute { return accounting.Attribute{Value: v, Count: 1} }
	actual, e := accounting.CanonicalKey(accounting.Raw{SourceIP: "10.203.11.40", NASIP: one("10.203.11.40"), Station: one(string(attrs[31][0])), Session: one(p.Scenario.Session)})
	if e != nil {
		return errors.New("native station invalid")
	}
	expected, e := accounting.CanonicalKey(accounting.Raw{SourceIP: p.Scenario.NAS, NASIP: one(p.Scenario.NAS), Station: one(p.Station), Session: one(p.Scenario.Session)})
	if e != nil || actual != expected {
		return errors.New("native request differs from chosen NAS/station")
	}
	return verifyNativeHMAC(packet, nil, secret)
}
func validateNativeEAPResponse(packet, request, secret []byte) (sc.EAPResult, string, error) {
	var result sc.EAPResult
	attrs, e := nativeEAPAttributes(packet)
	if e != nil {
		return result, "", e
	}
	var eapCode byte
	switch packet[0] {
	case 2:
		eapCode = 3
	case 3:
		eapCode = 4
	case 11:
		eapCode = 1
	default:
		return result, "", errors.New("unknown native EAP response")
	}
	if bytes.Join(attrs[79], nil)[0] != eapCode {
		return result, "", errors.New("native EAP/RADIUS outcome mismatch")
	}
	class, e := validateResponse(packet, request, secret, packet[0])
	if e != nil {
		return result, "", e
	}
	if e = verifyNativeHMAC(packet, request, secret); e != nil {
		return result, "", e
	}
	result.ResponseCode = int(packet[0])
	result.ResponseAuthenticatorSHA256 = digestBytes(packet[4:20])
	switch packet[0] {
	case 2:
		result.Accepted = true
		result.TunnelType = 13
		result.TunnelMediumType = 6
		result.VLAN = 120
	case 3:
		result.Rejected = true
	}
	return result, class, nil
}
