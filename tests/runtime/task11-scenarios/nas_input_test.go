package main

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"strings"
	"testing"
	"time"

	"github.com/CampusTech/cloud-8021x/tests/runtime/task11-acceptance/scenariocontract"
)

func pureNASInput(t *testing.T) nasPrivateInput {
	t.Helper()
	p := pureNASPlan()
	raw, e := json.Marshal(p)
	if e != nil {
		t.Fatal(e)
	}
	request := scenariocontract.Request{Schema: 1, AttemptID: "task11-" + strings.Repeat("1", 32), Sequence: 4, Action: "nas-native", Pins: scenariocontract.Pins{PlanSHA256: digestBytes(raw), PlatformSHA256: p.Scenario.PlatformSHA256, EnrollmentSHA256: p.Scenario.EnrollmentSHA256, ApplicationSHA256: p.Scenario.ApplicationSHA256, ScenarioSHA256: p.Scenario.SelfSHA256}}
	requestBytes, e := json.MarshalIndent(request, "", " ")
	if e != nil {
		t.Fatal(e)
	}
	requestBytes = append(append([]byte("\n"), requestBytes...), '\n')
	return nasPrivateInput{Schema: 1, RequestBytes: requestBytes, RequestSHA256: digestBytes(requestBytes), PlanBytes: raw, PlanSHA256: digestBytes(raw)}
}
func encodePureNASInput(t *testing.T, v nasPrivateInput) []byte {
	t.Helper()
	raw, e := json.Marshal(v)
	if e != nil {
		t.Fatal(e)
	}
	return raw
}
func TestPrivateNASInputPreservesExactRequestBytesAndRefusesUnboundInputs(t *testing.T) {
	v := pureNASInput(t)
	decoded, e := decodeNASInput(encodePureNASInput(t, v))
	if e != nil {
		t.Fatal(e)
	}
	if !bytes.Equal(decoded.RequestBytes, v.RequestBytes) || decoded.Request.Action != "nas-native" || decoded.Plan.Scenario.Session != "task11-independent-new" {
		t.Fatal("protected raw bytes were canonicalized or private plan replaced")
	}
	for _, kind := range []string{"request-pin", "plan-pin", "scenario-pin", "request-cap", "plan-cap", "foreign-action", "missing-prior", "irrelevant-prior", "unknown", "duplicate", "trailing", "outer-cap"} {
		t.Run(kind, func(t *testing.T) {
			input := pureNASInput(t)
			switch kind {
			case "request-pin":
				input.RequestSHA256 = strings.Repeat("0", 64)
			case "plan-pin":
				input.PlanSHA256 = strings.Repeat("0", 64)
			case "request-cap":
				input.RequestBytes = bytes.Repeat([]byte(" "), 65537)
				input.RequestSHA256 = digestBytes(input.RequestBytes)
			case "plan-cap":
				input.PlanBytes = bytes.Repeat([]byte(" "), 65537)
				input.PlanSHA256 = digestBytes(input.PlanBytes)
			case "scenario-pin", "foreign-action", "missing-prior":
				request, e := scenariocontract.DecodeRequest(input.RequestBytes)
				if e != nil {
					t.Fatal(e)
				}
				switch kind {
				case "scenario-pin":
					request.ScenarioSHA256 = strings.Repeat("9", 64)
				case "foreign-action":
					request.Action = "stop-postgres"
				case "missing-prior":
					request.Action = "nas-ca-adopted"
					request.Authority = "rsa"
					request.SelectionSHA256 = strings.Repeat("8", 64)
					request.IssuanceSequence = 1
				}
				input.RequestBytes, e = json.Marshal(request)
				if e != nil {
					t.Fatal(e)
				}
				input.RequestSHA256 = digestBytes(input.RequestBytes)
			case "irrelevant-prior":
				input.Prior = &nasPriorInput{SelectionBytes: []byte("{}"), ResultBytes: []byte("{}")}
			}
			raw := encodePureNASInput(t, input)
			switch kind {
			case "unknown":
				raw = append([]byte(`{"path":"/outside",`), raw[1:]...)
			case "duplicate":
				raw = append([]byte(`{"schema":1,`), raw[1:]...)
			case "trailing":
				raw = append(raw, []byte("{}")...)
			case "outer-cap":
				raw = bytes.Repeat([]byte(" "), (256<<10)+1)
			}
			if _, e := decodeNASInput(raw); e == nil {
				t.Fatal("unbound/private override or oversized input accepted")
			}
		})
	}
}

type purePriorMaterial struct {
	input                              nasPrivateInput
	key, root, intermediate, decrypter []byte
	now                                time.Time
	leaf                               *x509.Certificate
}

func purePriorNASInput(t *testing.T) purePriorMaterial {
	t.Helper()
	f := pureSCEPFixture(t)
	p := pureNASPlan()
	p.Scenario.Scenario = "ca-continuity"
	p.Scenario.Case = "ca-rsa-continuity"
	certPEM := func(c *x509.Certificate) []byte {
		return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
	}
	root, intermediate, decrypter := certPEM(f.root), certPEM(f.intermediate), certPEM(f.decrypter)
	keyDER, e := x509.MarshalPKCS8PrivateKey(f.clientKey)
	if e != nil {
		t.Fatal(e)
	}
	key := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	p.Materials["rsa-root.pem"] = digestBytes(root)
	p.RSA.RootSHA256 = digestBytes(root)
	p.Materials["rsa-intermediate.pem"] = digestBytes(intermediate)
	p.RSA.IntermediateSHA256 = digestBytes(intermediate)
	p.Materials["rsa-decrypter.pem"] = digestBytes(decrypter)
	p.RSA.DecrypterSHA256 = digestBytes(decrypter)
	p.Materials["scep-client.key"] = digestBytes(key)
	planBytes, e := json.Marshal(p)
	if e != nil {
		t.Fatal(e)
	}
	original := scenariocontract.Request{Schema: 1, AttemptID: "task11-" + strings.Repeat("1", 32), Sequence: 1, Action: "nas-ca-original", Authority: "rsa", Pins: scenariocontract.Pins{PlanSHA256: digestBytes(planBytes), PlatformSHA256: p.Scenario.PlatformSHA256, EnrollmentSHA256: p.Scenario.EnrollmentSHA256, ApplicationSHA256: p.Scenario.ApplicationSHA256, ScenarioSHA256: p.Scenario.SelfSHA256}}
	originalBytes, e := json.Marshal(original)
	if e != nil {
		t.Fatal(e)
	}
	originalBytes = append(originalBytes, '\n')
	public, e := x509.MarshalPKIXPublicKey(f.issued.PublicKey)
	if e != nil {
		t.Fatal(e)
	}
	result := scenariocontract.Result{Schema: 1, Kind: "scenario-operation", AttemptID: original.AttemptID, Sequence: 1, Action: original.Action, Pins: original.Pins, RequestSHA256: digestBytes(originalBytes), StartedAt: f.now, FinishedAt: f.now.Add(time.Second), Retired: true, CA: &scenariocontract.CAResult{Authority: "rsa", Route: "rsa-scep", Phase: "original", Peer: "10.203.11.31", RequestSHA256: digestBytes(f.request.Raw), SignerPublicSHA256: digestBytes(public), OriginalRootSHA256: p.RSA.RootSHA256, OriginalIntermediateSHA256: p.RSA.IntermediateSHA256, OriginalDecrypterSHA256: p.RSA.DecrypterSHA256, Issued: &scenariocontract.IssuedCertificate{Serial: f.issued.SerialNumber.String(), LeafDER: f.issued.Raw, LeafDERSHA256: digestBytes(f.issued.Raw), PublicKeySHA256: digestBytes(public), NotBefore: f.issued.NotBefore, NotAfter: f.issued.NotAfter, Subject: f.issued.Subject.String(), ClientAuthOnly: true}, Response: scenariocontract.CAResponse{HTTPStatus: 200, SignatureVerified: true, TransactionBound: true, ChainVerified: true}}}
	resultBytes, e := json.Marshal(result)
	if e != nil {
		t.Fatal(e)
	}
	selection := scenariocontract.CASelection{Schema: 1, AttemptID: original.AttemptID, IssuanceSequence: 1, ResultSHA256: digestBytes(resultBytes), Authority: "rsa", Serial: f.issued.SerialNumber.String(), LeafDERSHA256: digestBytes(f.issued.Raw), OriginalRootSHA256: p.RSA.RootSHA256, OriginalIntermediateSHA256: p.RSA.IntermediateSHA256}
	selectionBytes, e := json.Marshal(selection)
	if e != nil {
		t.Fatal(e)
	}
	current := original
	current.Sequence = 5
	current.Action = "nas-ca-adopted"
	current.SelectionSHA256 = digestBytes(selectionBytes)
	current.IssuanceSequence = 1
	requestBytes, e := json.Marshal(current)
	if e != nil {
		t.Fatal(e)
	}
	requestBytes = append(requestBytes, '\n')
	return purePriorMaterial{input: nasPrivateInput{Schema: 1, RequestBytes: requestBytes, RequestSHA256: digestBytes(requestBytes), PlanBytes: planBytes, PlanSHA256: digestBytes(planBytes), Prior: &nasPriorInput{SelectionBytes: selectionBytes, ResultBytes: resultBytes}}, key: key, root: root, intermediate: intermediate, decrypter: decrypter, now: f.now, leaf: f.issued}
}
func TestPriorRSARenewalRequiresOriginalRetiredSameAttemptResult(t *testing.T) {
	f := purePriorNASInput(t)
	decoded, e := decodeNASInput(encodePureNASInput(t, f.input))
	if e != nil {
		t.Fatal(e)
	}
	if decoded.PriorSelection == nil || decoded.PriorResult == nil || decoded.PriorSelection.Serial != f.leaf.SerialNumber.String() {
		t.Fatal("bound prior selection lost")
	}
	for _, kind := range []string{"selection-bytes", "result-bytes", "selection-cap", "result-cap", "other-attempt", "wrong-sequence", "not-retired", "adopted-result", "changed-serial", "changed-chain", "wrong-original-peer"} {
		t.Run(kind, func(t *testing.T) {
			v := f.input
			prior := *v.Prior
			prior.SelectionBytes = bytes.Clone(prior.SelectionBytes)
			prior.ResultBytes = bytes.Clone(prior.ResultBytes)
			v.Prior = &prior
			switch kind {
			case "selection-bytes":
				prior.SelectionBytes = append(prior.SelectionBytes, ' ')
			case "result-bytes":
				prior.ResultBytes = append(prior.ResultBytes, ' ')
			case "selection-cap":
				prior.SelectionBytes = bytes.Repeat([]byte(" "), 2049)
			case "result-cap":
				prior.ResultBytes = bytes.Repeat([]byte(" "), 32769)
			default:
				var selection scenariocontract.CASelection
				var result scenariocontract.Result
				if json.Unmarshal(prior.SelectionBytes, &selection) != nil || json.Unmarshal(prior.ResultBytes, &result) != nil {
					t.Fatal("fixture invalid")
				}
				switch kind {
				case "other-attempt":
					selection.AttemptID = "task11-" + strings.Repeat("2", 32)
				case "wrong-sequence":
					selection.IssuanceSequence = 2
				case "not-retired":
					result.Retired = false
				case "adopted-result":
					result.Action = "nas-ca-adopted"
					result.CA.Phase = "adopted"
					result.CA.Peer = "10.203.11.21"
				case "changed-serial":
					selection.Serial = "999"
				case "changed-chain":
					result.CA.OriginalRootSHA256 = strings.Repeat("9", 64)
				case "wrong-original-peer":
					result.CA.Peer = "10.203.11.32"
				}
				var e error
				prior.ResultBytes, e = json.Marshal(result)
				if e != nil {
					t.Fatal(e)
				}
				selection.ResultSHA256 = digestBytes(prior.ResultBytes)
				prior.SelectionBytes, e = json.Marshal(selection)
				if e != nil {
					t.Fatal(e)
				}
				request, e := scenariocontract.DecodeRequest(v.RequestBytes)
				if e != nil {
					t.Fatal(e)
				}
				request.SelectionSHA256 = digestBytes(prior.SelectionBytes)
				v.RequestBytes, e = json.Marshal(request)
				if e != nil {
					t.Fatal(e)
				}
				v.RequestSHA256 = digestBytes(v.RequestBytes)
			}
			if _, e := decodeNASInput(encodePureNASInput(t, v)); e == nil {
				t.Fatal("foreign/unretired/nonoriginal prior result accepted")
			}
		})
	}
}
func TestPriorRSALeafMustMatchPinnedClientKeyAndPreservedAuthority(t *testing.T) {
	f := purePriorNASInput(t)
	decoded, e := decodeNASInput(encodePureNASInput(t, f.input))
	if e != nil {
		t.Fatal(e)
	}
	leaf, e := verifyPriorRSACertificate(decoded, f.key, f.root, f.intermediate, f.decrypter, f.now)
	if e != nil {
		t.Fatal(e)
	}
	if !bytes.Equal(leaf.Raw, f.leaf.Raw) {
		t.Fatal("prior original DER replaced")
	}
	for _, kind := range []string{"key-bytes", "root-bytes", "intermediate-bytes", "decrypter-bytes", "expired", "different-pinned-valid-key", "different-pinned-valid-chain"} {
		candidate := decoded
		key, root, intermediate, decrypter, now := bytes.Clone(f.key), bytes.Clone(f.root), bytes.Clone(f.intermediate), bytes.Clone(f.decrypter), f.now
		switch kind {
		case "key-bytes":
			key = append(key, ' ')
		case "root-bytes":
			root = append(root, ' ')
		case "intermediate-bytes":
			intermediate = append(intermediate, ' ')
		case "decrypter-bytes":
			decrypter = append(decrypter, ' ')
		case "expired":
			now = f.leaf.NotAfter.Add(time.Second)
		case "different-pinned-valid-key":
			_, foreign := pureClientCredential(t, "different pinned client")
			der, err := x509.MarshalPKCS8PrivateKey(foreign)
			if err != nil {
				t.Fatal(err)
			}
			key = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
			materials := map[string]string{}
			for name, pin := range candidate.Plan.Materials {
				materials[name] = pin
			}
			candidate.Plan.Materials = materials
			candidate.Plan.Materials["scep-client.key"] = digestBytes(key)
		case "different-pinned-valid-chain":
			foreign := pureECFixture(t)
			root = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: foreign.root.Raw})
			intermediate = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: foreign.intermediate.Raw})
			candidate.Plan.RSA.RootSHA256 = digestBytes(root)
			candidate.Plan.RSA.IntermediateSHA256 = digestBytes(intermediate)
		}
		if _, e := verifyPriorRSACertificate(candidate, key, root, intermediate, decrypter, now); e == nil {
			t.Fatal("unbound key/authority or expired prior leaf accepted")
		}
	}
}
