package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"mime"
	"net/http"
	"strings"
	"time"

	"github.com/CampusTech/cloud-8021x/tests/runtime/task11-acceptance/scenariocontract"
	"github.com/smallstep/scep"
)

type caExecution struct {
	input                                 decodedNASInput
	phase, peer                           string
	root, intermediate, decrypter, signer *x509.Certificate
	key                                   *rsa.PrivateKey
	authorityClient, brokerClient         *http.Client
	brokerToken                           []byte
}

func prepareCAExecution(input decodedNASInput, material map[string][]byte, now time.Time) (*caExecution, error) {
	if now.IsZero() || caseAuthority(input.Plan.Scenario) != input.Request.Authority {
		return nil, errors.New("immutable CA authority/time required")
	}
	var phase string
	switch input.Request.Action {
	case "nas-ca-original":
		phase = "original"
	case "nas-ca-adopted":
		phase = "adopted"
	case "nas-ca-passive":
		phase = "passive"
	default:
		return nil, errors.New("fixed CA action required")
	}
	result := &caExecution{input: input, phase: phase}
	p := input.Plan
	if input.Request.Authority == "ec" {
		if p.EC.Phase != "original" {
			return nil, errors.New("preserved original EC plan required")
		}
		peer, e := phaseCAPeer(p.EC.Peer, phase)
		if e != nil {
			return nil, e
		}
		ecPlan := p.EC
		ecPlan.Phase = phase
		ecPlan.Peer = peer
		client, e := pinnedECClient(ecPlan, material["ec-root.pem"], material["ec-intermediate.pem"], material["client.pem"], material["client.key"])
		if e != nil {
			return nil, e
		}
		transport, ok := client.Transport.(*http.Transport)
		if !ok || transport.TLSClientConfig == nil || len(transport.TLSClientConfig.Certificates) != 1 || len(transport.TLSClientConfig.Certificates[0].Certificate) != 2 {
			return nil, errors.New("actual EC mTLS identity unavailable")
		}
		signer, e := x509.ParseCertificate(transport.TLSClientConfig.Certificates[0].Certificate[0])
		if e != nil {
			return nil, errors.New("actual EC mTLS leaf unavailable")
		}
		root, e := singlePinnedCertificate(material["ec-root.pem"], p.EC.RootSHA256)
		if e != nil {
			return nil, e
		}
		intermediate, e := singlePinnedCertificate(material["ec-intermediate.pem"], p.EC.IntermediateSHA256)
		if e != nil {
			return nil, e
		}
		result.peer = peer
		result.signer = signer
		result.root = root
		result.intermediate = intermediate
		result.authorityClient = client
		return result, nil
	}
	if input.Request.Authority != "rsa" {
		return nil, errors.New("unknown CA authority")
	}
	peer, e := phaseCAPeer(p.RSA.Blue, phase)
	if e != nil {
		return nil, e
	}
	key, e := parsePinnedRSAClientKey(p, material["scep-client.key"])
	if e != nil {
		return nil, e
	}
	root, e := singlePinnedCertificate(material["rsa-root.pem"], p.RSA.RootSHA256)
	if e != nil || !root.IsCA {
		return nil, errors.New("preserved RSA root unavailable")
	}
	intermediate, e := singlePinnedCertificate(material["rsa-intermediate.pem"], p.RSA.IntermediateSHA256)
	if e != nil || !intermediate.IsCA || intermediate.CheckSignatureFrom(root) != nil {
		return nil, errors.New("preserved RSA intermediate unavailable")
	}
	decrypter, e := singlePinnedCertificate(material["rsa-decrypter.pem"], p.RSA.DecrypterSHA256)
	if e != nil {
		return nil, e
	}
	var signer *x509.Certificate
	if phase == "original" {
		signer, e = initialSCEPSigner(key, now)
	} else {
		signer, e = verifyPriorRSACertificate(input, material["scep-client.key"], material["rsa-root.pem"], material["rsa-intermediate.pem"], material["rsa-decrypter.pem"], now)
	}
	if e != nil {
		return nil, e
	}
	broker, e := pinnedPhaseRSAClient(p.RSA, phase, material["rsa-root.pem"], material["broker.crt"], true, nil)
	if e != nil {
		return nil, e
	}
	authority, e := pinnedPhaseRSAClient(p.RSA, phase, material["rsa-root.pem"], material["broker.crt"], false, nil)
	if e != nil {
		return nil, e
	}
	token := material["broker-token"]
	if _, e = makeBrokerRequest(p.RSA, token, now); e != nil {
		return nil, e
	}
	result.peer = peer
	result.key = key
	result.root = root
	result.intermediate = intermediate
	result.decrypter = decrypter
	result.signer = signer
	result.authorityClient = authority
	result.brokerClient = broker
	result.brokerToken = append([]byte(nil), token...)
	return result, nil
}

// A self-signed client signer is required by the initial genuine SCEP protocol.
// It is never an authority-issued leaf or an installation/admission receipt.
func initialSCEPSigner(key *rsa.PrivateKey, now time.Time) (*x509.Certificate, error) {
	serial, e := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if e != nil {
		return nil, errors.New("SCEP client serial unavailable")
	}
	serial.Add(serial, big.NewInt(1))
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "task11-scep-client", OrganizationalUnit: []string{"task11-renewal-continuity"}}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, BasicConstraintsValid: true}
	der, e := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if e != nil {
		return nil, errors.New("genuine initial SCEP client signer unavailable")
	}
	signer, e := x509.ParseCertificate(der)
	if e != nil {
		return nil, errors.New("genuine SCEP client signer invalid")
	}
	return signer, nil
}
func executeCA(ctx context.Context, exchange *caExecution) (scenariocontract.CAResult, error) {
	var result scenariocontract.CAResult
	if ctx == nil || exchange == nil || exchange.signer == nil || exchange.authorityClient == nil {
		return result, errors.New("prepared fixed CA exchange required")
	}
	ctx, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()
	defer exchange.authorityClient.CloseIdleConnections()
	p := exchange.input.Plan
	result.Authority = exchange.input.Request.Authority
	result.Phase = exchange.phase
	result.Peer = exchange.peer
	public, e := x509.MarshalPKIXPublicKey(exchange.signer.PublicKey)
	if e != nil {
		return result, errors.New("actual CA client public key unavailable")
	}
	result.SignerPublicSHA256 = digestBytes(public)
	if result.Authority == "ec" {
		result.Route = "ec-legacy-mtls-renew"
		result.OriginalRootSHA256 = p.EC.RootSHA256
		result.OriginalIntermediateSHA256 = p.EC.IntermediateSHA256
		ecPlan := p.EC
		ecPlan.Phase = exchange.phase
		ecPlan.Peer = exchange.peer
		request, e := makeECRenewRequest(ecPlan)
		if e != nil {
			return result, e
		}
		result.RequestSHA256 = digestBytes(nil) // The ordinary mTLS renewal has no body/JWT.
		status, media, body, e := performCAHTTP(ctx, exchange.authorityClient, request, 32<<10)
		defer clear(body)
		result.Response.HTTPStatus = status
		if e != nil {
			result.Response.Code = "transport-unavailable"
			return result, nil
		}
		if status != http.StatusCreated {
			result.Response.Code = "http-status"
			return result, nil
		}
		if !caResponseMedia(media, "application/json") {
			result.Response.Code = "reply-invalid"
			return result, nil
		}
		leaf, e := verifyECRenewResponse(status, body, exchange.signer, exchange.root, exchange.intermediate, time.Now().UTC())
		if e != nil {
			return result, e
		}
		result.Issued, e = issuedCertificateBody(leaf)
		if e != nil {
			return result, e
		}
		result.Response.SignatureVerified = true
		result.Response.TransactionBound = true
		result.Response.ChainVerified = true
		return result, nil
	}
	if result.Authority != "rsa" || exchange.brokerClient == nil || exchange.key == nil || exchange.decrypter == nil {
		return result, errors.New("prepared RSA exchange unavailable")
	}
	defer exchange.brokerClient.CloseIdleConnections()
	defer clear(exchange.brokerToken)
	result.Route = "rsa-scep"
	result.OriginalRootSHA256 = p.RSA.RootSHA256
	result.OriginalIntermediateSHA256 = p.RSA.IntermediateSHA256
	result.OriginalDecrypterSHA256 = p.RSA.DecrypterSHA256
	result.RequestSHA256 = digestBytes(nil)
	brokerRequest, e := makeBrokerRequest(p.RSA, exchange.brokerToken, time.Now().UTC())
	if e != nil {
		return result, e
	}
	status, media, challengeBytes, e := performCAHTTP(ctx, exchange.brokerClient, brokerRequest, 4096)
	defer clear(challengeBytes)
	result.Response.HTTPStatus = status
	if e != nil {
		result.Response.Code = "broker-transport-unavailable"
		return result, nil
	}
	if status != http.StatusOK {
		result.Response.Code = "broker-http-status"
		return result, nil
	}
	challenge, e := brokerChallengeReply(status, media, challengeBytes)
	if e != nil {
		return result, e
	}
	message, e := makeSCEPRequest(exchange.key, exchange.signer, exchange.decrypter, challenge, exchange.phase != "original")
	if e != nil {
		return result, e
	}
	result.RequestSHA256 = digestBytes(message.Raw)
	operation, e := makeSCEPOperation(p.RSA, message.Raw)
	if e != nil {
		return result, e
	}
	status, media, replyBytes, e := performCAHTTP(ctx, exchange.authorityClient, operation, 32<<10)
	defer clear(replyBytes)
	result.Response.HTTPStatus = status
	if e != nil {
		result.Response.Code = "transport-unavailable"
		return result, nil
	}
	if status != http.StatusOK {
		result.Response.Code = "http-status"
		return result, nil
	}
	if !caResponseMedia(media, "application/x-pki-message") {
		return result, errors.New("actual SCEP response media differs")
	}
	observed, e := verifySCEPReply(replyBytes, message, exchange.signer, exchange.key, exchange.decrypter, exchange.root, exchange.intermediate, time.Now().UTC())
	if e != nil {
		return result, e
	}
	result.Response.SignatureVerified = observed.SignatureVerified
	result.Response.TransactionBound = observed.TransactionBound
	result.Response.ChainVerified = observed.ChainVerified
	if observed.Status == scep.FAILURE {
		result.Response.Code = "scep-failure-" + string(observed.FailCode)
		return result, nil
	}
	result.Issued, e = issuedCertificateBody(observed.Leaf)
	if e != nil {
		return result, e
	}
	return result, nil
}
func caResponseMedia(value, expected string) bool {
	media, parameters, e := mime.ParseMediaType(value)
	if e != nil || media != expected {
		return false
	}
	if expected != "application/json" {
		return len(parameters) == 0
	}
	if len(parameters) > 1 {
		return false
	}
	for name, v := range parameters {
		if name != "charset" || !strings.EqualFold(v, "utf-8") {
			return false
		}
	}
	return true
}
