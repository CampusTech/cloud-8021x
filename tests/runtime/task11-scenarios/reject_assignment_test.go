package main

import (
	"bytes"
	"strconv"
	"testing"
)

func TestAuthenticatedNativeRejectCannotCarryAssignment(t *testing.T) {
	secret := []byte("task11-private-nas-secret")
	request := pureEAPRequest(pureNASPlan(), secret)
	for _, kind := range []byte{25, 64, 65, 81} {
		t.Run("attribute-"+strconv.Itoa(int(kind)), func(t *testing.T) {
			attrs := attribute(79, []byte{4, 1, 0, 4})
			value := []byte("assignment")
			if kind == 64 || kind == 65 {
				value = []byte{0, 0, 0, 13}
			}
			attrs = append(attrs, attribute(kind, value)...)
			reply := pureEAPReply(t, request, secret, 3, attrs)
			if _, _, err := validateNativeEAPResponse(reply, request, secret); err == nil {
				t.Fatalf("authenticated reject with attribute %d accepted as assignment-free", kind)
			}
		})
	}
}

func TestNativeRejectRefusesEmptyAndDuplicateAssignment(t *testing.T) {
	secret := []byte("task11-private-nas-secret")
	request := pureEAPRequest(pureNASPlan(), secret)
	for _, kind := range []byte{25, 64, 65, 81} {
		for _, form := range []string{"empty", "duplicate"} {
			t.Run("attribute-"+strconv.Itoa(int(kind))+"-"+form, func(t *testing.T) {
				attrs := attribute(79, []byte{4, 1, 0, 4})
				attrs = append(attrs, attribute(kind, nil)...)
				if form == "duplicate" {
					attrs = append(attrs, attribute(kind, []byte("assignment"))...)
				}
				reply := pureEAPReply(t, request, secret, 3, attrs)
				if _, _, e := validateNativeEAPResponse(reply, request, secret); e == nil {
					t.Fatal("assignment presence accepted")
				}
			})
		}
	}
}

func TestAssignmentFreeNativeRejectPreservesAuthenticatorsAndUnrelatedAttributes(t *testing.T) {
	secret := []byte("task11-private-nas-secret")
	request := pureEAPRequest(pureNASPlan(), secret)
	attrs := append(attribute(79, []byte{4, 1, 0, 4}), attribute(18, []byte("synthetic rejection"))...)
	good := pureEAPReply(t, request, secret, 3, attrs)
	before := bytes.Clone(good)
	result, class, e := validateNativeEAPResponse(good, request, secret)
	if e != nil || !result.Rejected || result.Accepted || class != "" || result.TunnelType != 0 || result.TunnelMediumType != 0 || result.VLAN != 0 || !bytes.Equal(before, good) {
		t.Fatal("assignment-free authenticated reject changed", e)
	}
	for _, fault := range []string{"response-authenticator", "message-authenticator", "identifier", "eap-outcome"} {
		t.Run(fault, func(t *testing.T) {
			bad := bytes.Clone(good)
			switch fault {
			case "response-authenticator":
				bad[4] ^= 1
			case "message-authenticator":
				bad[len(bad)-1] ^= 1
				bad = signedServerReply(t, request, secret, 3, bad[20:])
			case "identifier":
				bad[1]++
			case "eap-outcome":
				bad = pureEAPReply(t, request, secret, 3, attribute(79, []byte{3, 1, 0, 4}))
			}
			if _, _, e := validateNativeEAPResponse(bad, request, secret); e == nil {
				t.Fatal("forged reject accepted", fault)
			}
		})
	}
}

func TestNativeChallengeAssignmentPolicyIsUnchanged(t *testing.T) {
	secret := []byte("task11-private-nas-secret")
	request := pureEAPRequest(pureNASPlan(), secret)
	attrs := attribute(79, []byte{1, 2, 0, 5, 13})
	for _, kind := range []byte{25, 64, 65, 81} {
		attrs = append(attrs, attribute(kind, []byte("existing challenge field"))...)
	}
	result, class, e := validateNativeEAPResponse(pureEAPReply(t, request, secret, 11, attrs), request, secret)
	if e != nil || result.ResponseCode != 11 || result.Accepted || result.Rejected || class != "" {
		t.Fatal("challenge policy changed", e)
	}
}
