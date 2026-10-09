package scenariocontract

import (
	"encoding/json"
	"strings"
	"testing"
)

// Build raw JSON before any Authority field is added to Request. These are wire
// contract fixtures only, never proof of a genuine preceding issuance/result.
func caRequestFields(t *testing.T, action, authority string) map[string]any {
	t.Helper()
	r := validRequest(action)
	r.Sequence = 3
	var fields map[string]any
	if err := json.Unmarshal(encodeRequest(t, r), &fields); err != nil {
		t.Fatal(err)
	}
	delete(fields, "authority")
	if authority != "" {
		fields["authority"] = authority
	}
	if authority == "rsa" && (action == "nas-ca-adopted" || action == "nas-ca-passive") {
		fields["selection_sha256"] = strings.Repeat("c", 64)
		fields["issuance_sequence"] = 1
	}
	return fields
}
func caRequestRaw(t *testing.T, fields map[string]any) []byte {
	t.Helper()
	raw, err := json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestCARequestsRequireExplicitAuthority(t *testing.T) {
	for _, phase := range []string{"original", "adopted", "passive"} {
		t.Run(phase, func(t *testing.T) {
			if _, err := DecodeRequest(caRequestRaw(t, caRequestFields(t, "nas-ca-"+phase, ""))); err == nil {
				t.Fatal("missing explicit CA authority accepted")
			}
		})
	}
}

func TestCARequestsAcceptExactAuthorityAndRenewalSelectors(t *testing.T) {
	for _, authority := range []string{"ec", "rsa"} {
		for _, phase := range []string{"original", "adopted", "passive"} {
			t.Run(authority+"-"+phase, func(t *testing.T) {
				fields := caRequestFields(t, "nas-ca-"+phase, authority)
				r, err := DecodeRequest(caRequestRaw(t, fields))
				if err != nil {
					t.Fatal("explicit authority and phase-specific renewal selector refused", err)
				}
				var encoded map[string]any
				if err := json.Unmarshal(encodeRequest(t, r), &encoded); err != nil || encoded["authority"] != authority {
					t.Fatal("explicit authority was not retained", err)
				}
				if authority == "rsa" && phase != "original" && (r.SelectionSHA256 != strings.Repeat("c", 64) || r.IssuanceSequence != 1) {
					t.Fatal("earlier RSA renewal selector was not retained")
				}
			})
		}
	}
	fields := caRequestFields(t, "nas-ca-adopted", "rsa")
	fields["sequence"] = MaxSequence
	fields["issuance_sequence"] = MaxSequence - 1
	if _, err := DecodeRequest(caRequestRaw(t, fields)); err != nil {
		t.Fatal("last bounded earlier issuance refused", err)
	}
}

func TestCARequestsRejectAuthorityAliasesAndAmbiguity(t *testing.T) {
	for _, authority := range []any{"", nil, "EC", "RSA", "other", 1} {
		fields := caRequestFields(t, "nas-ca-original", "ec")
		fields["authority"] = authority
		if _, err := DecodeRequest(caRequestRaw(t, fields)); err == nil {
			t.Fatal("noncanonical or empty CA authority accepted")
		}
	}
	for _, alias := range []string{"Authority", "AUTHORITY", "AuthorityName"} {
		fields := caRequestFields(t, "nas-ca-original", "ec")
		delete(fields, "authority")
		fields[alias] = "ec"
		if _, err := DecodeRequest(caRequestRaw(t, fields)); err == nil {
			t.Fatal("authority member alias accepted")
		}
	}
	raw := string(caRequestRaw(t, caRequestFields(t, "nas-ca-original", "ec")))
	for _, member := range []string{`"authority":"rsa"`, `"Authority":"ec"`, `"authorit\u0079":"ec"`} {
		duplicate := strings.Replace(raw, `"authority":"ec"`, `"authority":"ec",`+member, 1)
		if _, err := DecodeRequest([]byte(duplicate)); err == nil {
			t.Fatal("duplicate or semantic authority alias accepted")
		}
	}
}

func TestCARequestsForbidIrrelevantAndEmptyAuthorityPresence(t *testing.T) {
	for _, action := range []string{"probe-active-pair", "read-accounting", "stop-green-primary", "start-green-primary", "reboot-green-primary", "nas-native", "nas-ongoing", "nas-duplicates", "nas-outage", "read-ca-issued", "stop-postgres", "start-postgres", "intake-unavailable", "intake-ready", "probe-owned-cleanup"} {
		t.Run(action, func(t *testing.T) {
			fields := caRequestFields(t, action, "")
			switch bodyKind(action) {
			case "ledger":
				fields["node"] = "green-primary"
				fields["sessions"] = []string{"task11-one"}
			case "lifecycle":
				fields["node"] = "green-primary"
			case "ca_issued":
				fields["selection_sha256"] = strings.Repeat("c", 64)
				fields["issuance_sequence"] = 1
			}
			if _, err := DecodeRequest(caRequestRaw(t, fields)); err != nil {
				t.Fatal("control request failed independently of authority", err)
			}
			for _, authority := range []any{"", nil, "ec", "rsa"} {
				fields["authority"] = authority
				if _, err := DecodeRequest(caRequestRaw(t, fields)); err == nil {
					t.Fatal("irrelevant authority presence accepted")
				}
			}
		})
	}
}

func TestCARequestsForbidSelectorsForECAndOriginalRSA(t *testing.T) {
	for _, tc := range []struct{ authority, phase string }{{"ec", "original"}, {"ec", "adopted"}, {"ec", "passive"}, {"rsa", "original"}} {
		t.Run(tc.authority+"-"+tc.phase, func(t *testing.T) {
			for _, selector := range []struct {
				key   string
				value any
			}{{"selection_sha256", ""}, {"selection_sha256", nil}, {"selection_sha256", strings.Repeat("c", 64)}, {"issuance_sequence", 0}, {"issuance_sequence", nil}, {"issuance_sequence", 1}} {
				fields := caRequestFields(t, "nas-ca-"+tc.phase, tc.authority)
				fields[selector.key] = selector.value
				if _, err := DecodeRequest(caRequestRaw(t, fields)); err == nil {
					t.Fatal("irrelevant CA selector presence accepted")
				}
			}
		})
	}
}

func TestCARequestsRequireEarlierBoundedRSASelection(t *testing.T) {
	for _, phase := range []string{"adopted", "passive"} {
		for _, tc := range []struct {
			name   string
			change func(map[string]any)
		}{
			{"missing-selection", func(f map[string]any) { delete(f, "selection_sha256") }},
			{"empty-selection", func(f map[string]any) { f["selection_sha256"] = "" }},
			{"null-selection", func(f map[string]any) { f["selection_sha256"] = nil }},
			{"uppercase-selection", func(f map[string]any) { f["selection_sha256"] = strings.Repeat("C", 64) }},
			{"short-selection", func(f map[string]any) { f["selection_sha256"] = strings.Repeat("c", 63) }},
			{"missing-issuance", func(f map[string]any) { delete(f, "issuance_sequence") }},
			{"zero-issuance", func(f map[string]any) { f["issuance_sequence"] = 0 }},
			{"null-issuance", func(f map[string]any) { f["issuance_sequence"] = nil }},
			{"negative-issuance", func(f map[string]any) { f["issuance_sequence"] = -1 }},
			{"same-issuance", func(f map[string]any) { f["issuance_sequence"] = 3 }},
			{"future-issuance", func(f map[string]any) { f["issuance_sequence"] = 4 }},
			{"first-sequence", func(f map[string]any) { f["sequence"] = 1 }},
			{"selection-case-alias", func(f map[string]any) { f["Selection_sha256"] = f["selection_sha256"]; delete(f, "selection_sha256") }},
			{"issuance-case-alias", func(f map[string]any) {
				f["Issuance_sequence"] = f["issuance_sequence"]
				delete(f, "issuance_sequence")
			}},
		} {
			t.Run(phase+"-"+tc.name, func(t *testing.T) {
				fields := caRequestFields(t, "nas-ca-"+phase, "rsa")
				tc.change(fields)
				if _, err := DecodeRequest(caRequestRaw(t, fields)); err == nil {
					t.Fatal("missing, aliased or non-earlier RSA selector accepted")
				}
			})
		}
	}
}

func TestCAResultBindsRequestedAuthority(t *testing.T) {
	for _, authority := range []string{"ec", "rsa"} {
		for _, phase := range []string{"original", "adopted", "passive"} {
			t.Run(authority+"-"+phase, func(t *testing.T) {
				r, err := DecodeRequest(caRequestRaw(t, caRequestFields(t, "nas-ca-"+phase, authority)))
				if err != nil {
					t.Fatal(err)
				}
				v := resultFor(r)
				makeCA := func(a string) *CAResult {
					pin := strings.Repeat("e", 64)
					peer := "10.203.11.21"
					if phase == "original" {
						peer = "10.203.11.31"
					}
					c := &CAResult{Authority: a, Route: "ec-legacy-mtls-renew", Phase: phase, Peer: peer, RequestSHA256: pin, SignerPublicSHA256: pin, OriginalRootSHA256: pin, OriginalIntermediateSHA256: pin, Response: CAResponse{HTTPStatus: 403, Code: "synthetic-refusal"}}
					if a == "rsa" {
						c.Route = "rsa-scep"
						c.OriginalDecrypterSHA256 = pin
					}
					return c
				}
				v.CA = makeCA(authority)
				raw, _ := json.Marshal(v)
				if _, err := DecodeResult(raw, r, v.RequestSHA256); err != nil {
					t.Fatal("matching authority result refused", err)
				}
				other := "rsa"
				if authority == "rsa" {
					other = "ec"
				}
				v.CA = makeCA(other)
				raw, _ = json.Marshal(v)
				if _, err := DecodeResult(raw, r, v.RequestSHA256); err == nil {
					t.Fatal("fully valid alternate authority result substituted for explicit request")
				}
			})
		}
	}
}
