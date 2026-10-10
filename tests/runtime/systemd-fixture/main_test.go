package main

import (
	"bytes"
	"crypto/md5"
	"testing"
)

func TestRebootRequiresPhysicalNodeChangeAndArtifactContinuity(t *testing.T) {
	a := snapshot{Schema: 1, Hostname: "task11-green-primary", BootID: "first", FileHashes: map[string]string{"/installed": "digest"}}
	b := a
	if compareReboot(a, b) == nil {
		t.Fatal("same boot was accepted")
	}
	b.BootID = "second"
	if err := compareReboot(a, b); err != nil {
		t.Fatal(err)
	}
	b.Hostname = "task11-green-secondary"
	if compareReboot(a, b) == nil {
		t.Fatal("different physical node accepted")
	}
	b.Hostname = a.Hostname
	b.FileHashes = map[string]string{"/installed": "changed"}
	if compareReboot(a, b) == nil {
		t.Fatal("artifact changed across reboot")
	}
}
func TestRADIUSReplyAuthenticationAndMalformedAttributes(t *testing.T) {
	secret := []byte("task11-synthetic-radius-key")
	request := append([]byte{4, 19, 0, 20}, bytes.Repeat([]byte{1}, 16)...)
	reply := append([]byte{5, 19, 0, 20}, make([]byte, 16)...)
	signed := append([]byte(nil), reply...)
	copy(signed[4:20], request[4:20])
	sum := md5.Sum(append(signed, secret...))
	copy(reply[4:20], sum[:])
	if err := verifyResponse(reply, request, secret); err != nil {
		t.Fatal(err)
	}
	reply[4] ^= 1
	if verifyResponse(reply, request, secret) == nil {
		t.Fatal("forged accounting ACK accepted")
	}
	malformed := append([]byte{2, 1, 0, 22}, make([]byte, 16)...)
	malformed = append(malformed, 25, 1)
	if _, err := attributes(malformed); err == nil {
		t.Fatal("zero-length attribute accepted")
	}
}
