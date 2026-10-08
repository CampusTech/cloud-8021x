package policy

import (
	"encoding/json"
	"errors"
	"strconv"

	"github.com/CampusTech/cloud-8021x/internal/domain"
)

// Native JSON is emitted by rlm_rest's encoder (body=json, raw_value=yes).
// No NAS string is interpolated into JSON. Only server-overwritten internal
// attributes select client/source/handoff; duplicate packet values remain arrays.
func decodeNative(data []byte) (Request, error) {
	var attrs map[string]struct {
		Type  string            `json:"type"`
		Value []json.RawMessage `json:"value"`
	}
	var r Request
	if err := domain.DecodeJSONStrict(data, &attrs); err != nil {
		return r, errors.New("invalid native REST payload")
	}
	values := func(key, kind string) ([]string, error) {
		a, ok := attrs[key]
		if !ok {
			return nil, nil
		}
		// Match the native packet's max_attributes bound. In particular, many
		// duplicate port values must reach the conservative no-VLAN policy.
		if a.Type != kind || len(a.Value) > 200 {
			return nil, errors.New("invalid native attribute type or count")
		}
		out := make([]string, 0, len(a.Value))
		for _, raw := range a.Value {
			var s string
			if kind == "integer" {
				var n uint32
				if json.Unmarshal(raw, &n) != nil {
					return nil, errors.New("invalid native integer")
				}
				s = strconv.FormatUint(uint64(n), 10)
			} else if json.Unmarshal(raw, &s) != nil || len(s) > 4096 {
				return nil, errors.New("invalid native string")
			}
			out = append(out, s)
		}
		return out, nil
	}
	client, e := values("C8021X-Client", "string")
	if e != nil || len(client) != 1 {
		return r, errors.New("invalid native client")
	}
	source, e := values("C8021X-Source", "string")
	if e != nil || len(source) != 1 {
		return r, errors.New("invalid native source")
	}
	r.Server = ServerContext{ClientID: client[0], SourceIP: source[0]}
	for _, v := range []struct {
		key, kind string
		dest      *[]string
	}{{"C8021X-Handoff", "string", &r.HandoffTokens}, {"TLS-Client-Cert-Common-Name", "string", &r.CertificateCommonNames}, {"Calling-Station-Id", "string", &r.CallingStations}, {"NAS-Port-Type", "integer", &r.NASPortTypes}} {
		*v.dest, e = values(v.key, v.kind)
		if e != nil {
			return r, e
		}
	}
	// Fingerprint mode carries the exact handoff; TLS CN is display-only there.
	if len(r.HandoffTokens) > 0 {
		r.CertificateCommonNames = nil
	}
	return r, nil
}
