package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/CampusTech/cloud-8021x/internal/adoption"
)

func TestSQLObservationPreservesPGPayloadForActualRecoveryRequest(t *testing.T) {
	// The wide synthetic enrollment value stresses the wire codec, not a valid
	// enrollment date. Structural spaces match PostgreSQL jsonb text output.
	original := []byte(`{"host_id": 2, "host_uuid": "22222222-3333-4444-8555-666666666666", "enrolled_at": 9007199254740993, "transport": "windows", "command_uuid": "actual-command", "script": "Write-Output \"<&>\"\n# Collection nonce: actual-command\n"}`)
	if !json.Valid(original) {
		t.Fatal("invalid regression input")
	}
	before := sqlObservation{Snapshot: durableSnapshot{Work: []durableWork{{ID: "fleet-cert:actual", Kind: "fleet-cert:collection", Generation: 7, Payload: original}}}}
	var wire bytes.Buffer
	if err := encodeSQLObservation(&wire, before); err != nil {
		t.Fatal(err)
	}
	after, err := decodeSQLObservation(wire.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	request := workRecoveryRequest(after.Snapshot.Work[0], strings.Repeat("a", 64))
	if request.PayloadSHA256 != adoption.Digest(original) {
		t.Fatalf("shipping original-payload guard would refuse: original=%s transported=%s", adoption.Digest(original), request.PayloadSHA256)
	}
	if !bytes.Equal(after.Snapshot.Work[0].Payload, original) {
		t.Fatal("PG payload bytes changed")
	}
	var payload collectionPayload
	if err = decodeExactJSON(after.Snapshot.Work[0].Payload, &payload); err != nil {
		t.Fatal(err)
	}
	if payload.EnrolledAt.String() != "9007199254740993" || payload.Script != "Write-Output \"<&>\"\n# Collection nonce: actual-command\n" {
		t.Fatal("exact numeric or script value changed")
	}
	argv, err := recoveryCommand(request)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(argv, " "), "--payload-sha256 "+adoption.Digest(original)) {
		t.Fatal("real recovery argv lost original digest")
	}
}

func TestSQLObservationAccountsForOpaqueExpansionBeforeWriting(t *testing.T) {
	// Exactly the old raw allowance needs 32MiB base64 plus the envelope. The
	// complete encoded response must refuse before any private partial output.
	payload := []byte(`{"x":"` + strings.Repeat("a", (24<<20)-8) + `"}`)
	v := sqlObservation{Snapshot: durableSnapshot{Work: []durableWork{{Payload: payload}}}}
	var out bytes.Buffer
	if err := encodeSQLObservation(&out, v); err == nil {
		t.Fatal("raw payload budget ignored base64/envelope expansion")
	}
	if out.Len() != 0 {
		t.Fatal("oversized private observation partially emitted")
	}
}

func TestSQLObservationRejectsMalformedOpaquePayloads(t *testing.T) {
	for name, payload := range map[string][]byte{
		"duplicate-key":  []byte(`{"host_id":2,"host_id":1}`),
		"trailing-value": []byte(`{"host_id":2} {"host_id":1}`),
		"null":           []byte(`null`),
		"array":          []byte(`[2,1]`),
		"invalid-escape": []byte(`{"script":"\q"}`),
	} {
		t.Run(name, func(t *testing.T) {
			v := sqlObservation{Snapshot: durableSnapshot{Work: []durableWork{{Payload: payload}}}}
			raw, err := json.Marshal(v)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = decodeSQLObservation(raw); err == nil {
				t.Fatal("opaque transport bypassed independent strict payload validation")
			}
			var out bytes.Buffer
			if err = encodeSQLObservation(&out, v); err == nil || out.Len() != 0 {
				t.Fatal("invalid payload emitted")
			}
		})
	}
	if _, err := decodeSQLObservation([]byte(`{"Snapshot":{"Work":[{"Payload":"!invalid-base64!"}]}}`)); err == nil {
		t.Fatal("malformed byte encoding accepted")
	}
}

func TestSQLObservationRejectsRawAndRowOverflows(t *testing.T) {
	v := sqlObservation{Snapshot: durableSnapshot{Work: []durableWork{{Payload: []byte(`{"x":"` + strings.Repeat("a", (24<<20)-7) + `"}`)}}}}
	if err := validateSQLObservation(v); err == nil {
		t.Fatal("raw byte budget exceeded")
	}
	v = sqlObservation{Snapshot: durableSnapshot{Work: make([]durableWork, 1153)}}
	if err := validateSQLObservation(v); err == nil {
		t.Fatal("work count exceeded")
	}
	v = sqlObservation{Snapshot: durableSnapshot{Guards: make([]durableGuard, 129)}}
	if err := validateSQLObservation(v); err == nil {
		t.Fatal("guard count exceeded")
	}
	if _, err := decodeSQLObservation(make([]byte, sqlWireLimit+1)); err == nil {
		t.Fatal("wire budget exceeded")
	}
}
