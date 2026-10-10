package main

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"time"

	"github.com/CampusTech/cloud-8021x/tests/runtime/task11-acceptance/scenariocontract"
)

type nasPriorInput struct {
	SelectionBytes []byte `json:"selection_bytes"`
	ResultBytes    []byte `json:"result_bytes"`
}

// Opaque bytes preserve the exact protected records, including boundary
// whitespace. The controller verifies stored provenance before private handoff.
type nasPrivateInput struct {
	Schema        int            `json:"schema"`
	RequestBytes  []byte         `json:"request_bytes"`
	RequestSHA256 string         `json:"request_sha256"`
	PlanBytes     []byte         `json:"plan_bytes"`
	PlanSHA256    string         `json:"plan_sha256"`
	Prior         *nasPriorInput `json:"prior,omitempty"`
}
type decodedNASInput struct {
	Request        scenariocontract.Request
	RequestBytes   []byte
	Plan           nasPrivatePlan
	PriorSelection *scenariocontract.CASelection
	PriorResult    *scenariocontract.Result
}

func decodeNASInput(raw []byte) (decodedNASInput, error) {
	input, e := decodeNASInputCore(raw)
	if e != nil {
		return input, e
	}
	switch input.Request.Action {
	case "nas-native", "nas-ongoing", "nas-duplicates", "nas-outage", "nas-ca-original", "nas-ca-adopted", "nas-ca-passive":
		return input, nil
	default:
		return decodedNASInput{}, errors.New("fixed NAS action required")
	}
}
func exactPrivateFields(raw []byte, required []string, optional string) error {
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil || fields == nil {
		return errors.New("private object required")
	}
	allowed := map[string]bool{}
	for _, key := range required {
		allowed[key] = true
		if _, ok := fields[key]; !ok {
			return errors.New("exact private fields required")
		}
	}
	if optional != "" {
		allowed[optional] = true
	}
	for key := range fields {
		if !allowed[key] {
			return errors.New("unknown private field refused")
		}
	}
	return nil
}
func decodeNASInputCore(raw []byte) (decodedNASInput, error) {
	var out decodedNASInput
	var in nasPrivateInput
	if strictJSON(raw, 256<<10, &in) != nil || exactPrivateFields(raw, []string{"schema", "request_bytes", "request_sha256", "plan_bytes", "plan_sha256"}, "prior") != nil || in.Schema != 1 || len(in.RequestBytes) > 64<<10 || len(in.PlanBytes) > 64<<10 || !shaPattern.MatchString(in.RequestSHA256) || digestBytes(in.RequestBytes) != in.RequestSHA256 {
		return out, errors.New("exact bounded private NAS byte envelope required")
	}
	request, e := scenariocontract.DecodeRequest(in.RequestBytes)
	if e != nil {
		return out, errors.New("sole shared Request refused private bytes")
	}
	plan, e := decodeNASPlan(in.PlanBytes, in.PlanSHA256)
	if e != nil {
		return out, e
	}
	p := plan.Scenario
	if request.PlanSHA256 != in.PlanSHA256 || request.PlatformSHA256 != p.PlatformSHA256 || request.EnrollmentSHA256 != p.EnrollmentSHA256 || request.ApplicationSHA256 != p.ApplicationSHA256 || request.ScenarioSHA256 != p.SelfSHA256 {
		return out, errors.New("private plan differs from independently pinned Request")
	}
	if e = validateCaseRequest(p, request); e != nil {
		return out, e
	}
	out.Request = request
	out.RequestBytes = bytes.Clone(in.RequestBytes)
	out.Plan = plan
	required := request.Authority == "rsa" && (request.Action == "nas-ca-adopted" || request.Action == "nas-ca-passive")
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil {
		return decodedNASInput{}, errors.New("private envelope invalid")
	}
	if !required {
		if _, present := fields["prior"]; present {
			return decodedNASInput{}, errors.New("irrelevant prior input presence refused")
		}
		return out, nil
	}
	if in.Prior == nil || len(in.Prior.SelectionBytes) == 0 || len(in.Prior.SelectionBytes) > 2048 || len(in.Prior.ResultBytes) == 0 || len(in.Prior.ResultBytes) > 32<<10 || exactPrivateFields(fields["prior"], []string{"selection_bytes", "result_bytes"}, "") != nil || digestBytes(in.Prior.SelectionBytes) != request.SelectionSHA256 {
		return decodedNASInput{}, errors.New("independently bound prior RSA inputs required")
	}
	selection, e := scenariocontract.DecodeCASelection(in.Prior.SelectionBytes)
	if e != nil || selection.Authority != "rsa" || selection.AttemptID != request.AttemptID || selection.IssuanceSequence != request.IssuanceSequence || selection.ResultSHA256 != digestBytes(in.Prior.ResultBytes) || selection.OriginalRootSHA256 != plan.RSA.RootSHA256 || selection.OriginalIntermediateSHA256 != plan.RSA.IntermediateSHA256 {
		return decodedNASInput{}, errors.New("original same-attempt RSA selection differs")
	}
	// Controller has already authenticated these exact result bytes against its
	// retired stored prior request. Selection pins their complete byte identity;
	// do not reconstruct opaque payloads or claim retirement from metadata alone.
	var peek struct {
		RequestSHA256 string `json:"request_sha256"`
	}
	if json.Unmarshal(in.Prior.ResultBytes, &peek) != nil {
		return decodedNASInput{}, errors.New("prior result invalid")
	}
	original := request
	original.Sequence = request.IssuanceSequence
	original.Action = "nas-ca-original"
	original.SelectionSHA256 = ""
	original.IssuanceSequence = 0
	result, e := scenariocontract.DecodeResult(in.Prior.ResultBytes, original, peek.RequestSHA256)
	if e != nil || result.CA == nil || result.CA.Issued == nil || result.CA.Peer != plan.RSA.Blue || result.CA.OriginalRootSHA256 != plan.RSA.RootSHA256 || result.CA.OriginalIntermediateSHA256 != plan.RSA.IntermediateSHA256 || result.CA.OriginalDecrypterSHA256 != plan.RSA.DecrypterSHA256 || result.CA.Issued.Serial != selection.Serial || result.CA.Issued.LeafDERSHA256 != selection.LeafDERSHA256 {
		return decodedNASInput{}, errors.New("retired original RSA result differs from pinned selection/authority")
	}
	out.PriorSelection = &selection
	out.PriorResult = &result
	return out, nil
}
func validateCaseRequest(p scenarioPlan, r scenariocontract.Request) error {
	authority := caseAuthority(p)
	if authority != "" {
		switch r.Action {
		case "nas-ca-original", "nas-ca-adopted", "nas-ca-passive":
			if r.Authority != authority {
				return errors.New("requested authority differs from immutable case")
			}
			return nil
		case "read-ca-issued":
			return nil
		default:
			return errors.New("action outside immutable CA case")
		}
	}
	actions, e := accountingRequests(p, r.AttemptID, r.PlanSHA256)
	if e != nil {
		return e
	}
	for _, allowed := range actions {
		if allowed.Action == r.Action {
			if r.Node != allowed.Node || len(r.Sessions) != len(allowed.Sessions) {
				return errors.New("requested Node/Sessions differ from immutable case")
			}
			for i, value := range allowed.Sessions {
				if r.Sessions[i] != value {
					return errors.New("requested Session differs from immutable case")
				}
			}
			return nil
		}
	}
	return errors.New("action outside immutable accounting case")
}
func parsePinnedRSAClientKey(p nasPrivatePlan, keyPEM []byte) (*rsa.PrivateKey, error) {
	if len(keyPEM) == 0 || len(keyPEM) > 16<<10 || digestBytes(keyPEM) != p.Materials["scep-client.key"] {
		return nil, errors.New("pinned persistent RSA client key unavailable")
	}
	block, rest := pem.Decode(keyPEM)
	if block == nil || block.Type != "PRIVATE KEY" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("single PKCS8 synthetic client key required")
	}
	defer clear(block.Bytes)
	parsed, e := x509.ParsePKCS8PrivateKey(block.Bytes)
	key, ok := parsed.(*rsa.PrivateKey)
	if e != nil || !ok || key.N == nil || key.N.BitLen() < 2048 || key.D == nil || key.D.Sign() <= 0 || len(key.Primes) < 2 || key.Validate() != nil {
		return nil, errors.New("valid persistent RSA2048 client key required")
	}
	return key, nil
}
func verifyPriorRSACertificate(input decodedNASInput, keyPEM, rootPEM, intermediatePEM, decrypterPEM []byte, now time.Time) (*x509.Certificate, error) {
	if input.PriorSelection == nil || input.PriorResult == nil || input.PriorResult.CA == nil || input.PriorResult.CA.Issued == nil || input.Request.Authority != "rsa" || (input.Request.Action != "nas-ca-adopted" && input.Request.Action != "nas-ca-passive") || now.IsZero() {
		return nil, errors.New("bound original RSA renewal input required")
	}
	p := input.Plan
	key, e := parsePinnedRSAClientKey(p, keyPEM)
	if e != nil {
		return nil, e
	}
	root, e := singlePinnedCertificate(rootPEM, p.RSA.RootSHA256)
	if e != nil || !root.IsCA {
		return nil, errors.New("preserved RSA root required")
	}
	intermediate, e := singlePinnedCertificate(intermediatePEM, p.RSA.IntermediateSHA256)
	if e != nil || !intermediate.IsCA || intermediate.CheckSignatureFrom(root) != nil {
		return nil, errors.New("preserved RSA intermediate required")
	}
	decrypter, e := singlePinnedCertificate(decrypterPEM, p.RSA.DecrypterSHA256)
	if e != nil {
		return nil, errors.New("preserved public SCEP decrypter required")
	}
	publicRA, ok := decrypter.PublicKey.(*rsa.PublicKey)
	if !ok || publicRA.N == nil || publicRA.N.BitLen() < 2048 || publicRA.E < 3 || publicRA.E%2 == 0 {
		return nil, errors.New("public SCEP RSA decrypter invalid")
	}
	issued := input.PriorResult.CA.Issued
	leaf, e := x509.ParseCertificate(issued.LeafDER)
	if e != nil || leaf.IsCA || leaf.SerialNumber.Sign() <= 0 || leaf.SerialNumber.String() != input.PriorSelection.Serial || digestBytes(leaf.Raw) != input.PriorSelection.LeafDERSHA256 || leaf.Subject.CommonName != "cloud-8021x-inventory" || len(leaf.Subject.OrganizationalUnit) != 1 || leaf.Subject.OrganizationalUnit[0] != "task11-renewal-continuity" || leaf.KeyUsage != (x509.KeyUsageDigitalSignature|x509.KeyUsageKeyEncipherment) || len(leaf.ExtKeyUsage) != 1 || leaf.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth || len(leaf.UnknownExtKeyUsage) != 0 || len(leaf.DNSNames)+len(leaf.IPAddresses)+len(leaf.EmailAddresses)+len(leaf.URIs) != 0 || !bytes.Equal(leaf.RawIssuer, intermediate.RawSubject) {
		return nil, errors.New("prior inventory-only client constraints differ")
	}
	public, e := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if e != nil {
		return nil, errors.New("persistent client public key unavailable")
	}
	actual, e := x509.MarshalPKIXPublicKey(leaf.PublicKey)
	if e != nil || !bytes.Equal(public, actual) || digestBytes(public) != issued.PublicKeySHA256 || digestBytes(public) != input.PriorResult.CA.SignerPublicSHA256 {
		return nil, errors.New("prior issued leaf differs from persistent synthetic client key")
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)
	intermediates := x509.NewCertPool()
	intermediates.AddCert(intermediate)
	if _, e = leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); e != nil {
		return nil, errors.New("prior original issued client chain invalid")
	}
	return leaf, nil
}
