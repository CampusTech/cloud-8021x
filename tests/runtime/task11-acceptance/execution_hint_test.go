package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestRemoteExecutionHintNeverSuppliesExpectedPayloadOrCommandAuthority(t *testing.T) {
	pin := strings.Repeat("a", 64)
	c := commandExpectation{Origin: "green-work", UUID: "actual-command", HostID: 2, HostUUID: syntheticWindows, Transport: "windows"}
	row := map[string]any{"command_uuid": c.UUID, "host_id": 2, "host_uuid": c.HostUUID, "request_type": "Script", "execution_id": "learned-execution", "script_contents": "untrusted remote body", "posts": 1}
	state := map[string]any{"schema": 1, "seed_sha256": pin, "commands": map[string]any{c.UUID: row}}
	raw, _ := json.Marshal(state)
	got, err := remoteExecutionHint(raw, pin, c)
	if err != nil || got != "learned-execution" {
		t.Fatal("actual learned hint lost", err)
	}
	for key, value := range map[string]any{"host_id": 1, "host_uuid": syntheticDevice, "request_type": "CertificateList", "command_uuid": "other", "execution_id": "a,b", "posts": 0} {
		prior := row[key]
		row[key] = value
		bad, _ := json.Marshal(state)
		if _, err = remoteExecutionHint(bad, pin, c); err == nil {
			t.Fatal("wrong remote hint target accepted", key)
		}
		row[key] = prior
	}
	if _, err = remoteExecutionHint(raw, strings.Repeat("b", 64), c); err == nil {
		t.Fatal("different seed accepted")
	}
	c.Transport = "apple"
	if _, err = remoteExecutionHint(raw, pin, c); err == nil {
		t.Fatal("Apple command gained remote execution hint")
	}
}
