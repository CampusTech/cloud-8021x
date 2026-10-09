package main

import (
	"encoding/json"
	"errors"
	"io"

	"github.com/CampusTech/cloud-8021x/internal/telemetry"
)

const sqlRawLimit = 24 << 20
const sqlWireLimit = 32 << 20

type sqlObservation struct {
	Snapshot                                     durableSnapshot
	ConfigSHA256, InventorySHA256, DisplaySHA256 string
	Records                                      []telemetry.BusinessRecord
	Outbox                                       []outboxExpectation
	Enabled, Blocked                             bool
	Ready                                        int
}

func validateSQLObservation(v sqlObservation) error {
	if len(v.Snapshot.Work) > 1152 || len(v.Snapshot.Guards) > 128 {
		return errors.New("SQL observation row bound exceeded")
	}
	budget := sqlRawLimit
	for _, w := range v.Snapshot.Work {
		budget -= len(w.Payload) + len(w.Receipt) + len(w.AttemptReceipt) + len(w.RecoveryEvidence)
		if budget < 0 {
			return errors.New("SQL observation raw byte bound exceeded")
		}
		// Base64 is a byte transport, not permission to carry arbitrary or ambiguous
		// JSON. Validate independently before projection/hashing, without rewriting.
		var object map[string]json.RawMessage
		if decodeExactJSON(w.Payload, &object) != nil || object == nil {
			return errors.New("SQL observation opaque payload is not a strict JSON object")
		}
	}
	for _, g := range v.Snapshot.Guards {
		h, err := json.Marshal(g.Host)
		if err != nil {
			return err
		}
		c, err := json.Marshal(g.Command)
		if err != nil {
			return err
		}
		budget -= len(h) + len(c) + len(g.Evidence)
		if budget < 0 {
			return errors.New("SQL observation raw byte bound exceeded")
		}
	}
	return nil
}
func encodeSQLObservation(out io.Writer, v sqlObservation) error {
	if err := validateSQLObservation(v); err != nil {
		return err
	}
	// Retain the raw24MiB maximum, but independently bound the entire encoded
	// response, including base64 expansion, projected records and metadata.
	buffer := boundedBuffer{limit: sqlWireLimit}
	defer func() { clear(buffer.buffer.Bytes()) }()
	if err := json.NewEncoder(&buffer).Encode(v); err != nil {
		return err
	}
	n, err := out.Write(buffer.buffer.Bytes())
	if err == nil && n != buffer.buffer.Len() {
		return io.ErrShortWrite
	}
	return err
}
func decodeSQLObservation(raw []byte) (sqlObservation, error) {
	var v sqlObservation
	if len(raw) > sqlWireLimit {
		return v, errors.New("SQL observation wire bound exceeded")
	}
	if err := decodeExactJSON(raw, &v); err != nil {
		return v, err
	}
	return v, validateSQLObservation(v)
}
