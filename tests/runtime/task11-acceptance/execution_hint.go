package main

import (
	"encoding/json"
	"errors"
	"regexp"
)

var executionIdentity = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,252}$`)

// Remote state is only a source of untrusted result locator hints. The shipping
// GET-only recovery independently verifies the original SQL script, nonce and
// enrollment. This function never copies a request, script or expected record.
func remoteExecutionHint(raw []byte, seed string, c commandExpectation) (string, error) {
	if len(raw) > 32<<20 || !validSHA(seed) || c.Origin != "green-work" || c.Transport != "windows" || c.HostID != 2 || c.HostUUID != syntheticWindows {
		return "", errors.New("fixed Windows hint scope required")
	}
	var top map[string]json.RawMessage
	if decodeExactJSON(raw, &top) != nil {
		return "", errors.New("private remote snapshot invalid")
	}
	var schema int
	var pin string
	var commands map[string]json.RawMessage
	if json.Unmarshal(top["schema"], &schema) != nil || schema != 1 || json.Unmarshal(top["seed_sha256"], &pin) != nil || pin != seed || decodeExactJSON(top["commands"], &commands) != nil || len(commands) > 128 {
		return "", errors.New("private remote snapshot binding differs")
	}
	var row map[string]json.RawMessage
	if decodeExactJSON(commands[c.UUID], &row) != nil {
		return "", errors.New("actual remote command missing")
	}
	var uuid, host, kind, execution string
	var id, posts int
	if json.Unmarshal(row["command_uuid"], &uuid) != nil || uuid != c.UUID || json.Unmarshal(row["host_uuid"], &host) != nil || host != c.HostUUID || json.Unmarshal(row["host_id"], &id) != nil || id != c.HostID || json.Unmarshal(row["request_type"], &kind) != nil || kind != "Script" || json.Unmarshal(row["posts"], &posts) != nil || posts != 1 || json.Unmarshal(row["execution_id"], &execution) != nil || !executionIdentity.MatchString(execution) {
		return "", errors.New("remote hint is not the bounded original Windows target")
	}
	return execution, nil
}
