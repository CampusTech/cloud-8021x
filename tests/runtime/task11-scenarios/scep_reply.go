package main

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/smallstep/scep"
)

type scepObservation struct {
	Leaf                                               *x509.Certificate
	Status                                             scep.PKIStatus
	FailCode                                           scep.FailInfo
	SignatureVerified, TransactionBound, ChainVerified bool
}

func verifySCEPReply(raw []byte, request *scep.PKIMessage, signer *x509.Certificate, key *rsa.PrivateKey, ra, root, intermediate *x509.Certificate, now time.Time) (scepObservation, error) {
	var result scepObservation
	if len(raw) == 0 || len(raw) > 32<<10 || request == nil || len(request.Raw) == 0 || len(request.Raw) > 32<<10 || signer == nil || key == nil || key.N == nil || key.N.BitLen() < 2048 || key.Validate() != nil || ra == nil || root == nil || intermediate == nil || now.IsZero() || !root.IsCA || !intermediate.IsCA || intermediate.CheckSignatureFrom(root) != nil {
		return result, errors.New("bounded original SCEP exchange inputs required")
	}
	public, e := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if e != nil {
		return result, errors.New("client key unavailable")
	}
	expected, e := x509.MarshalPKIXPublicKey(signer.PublicKey)
	if e != nil || !bytes.Equal(public, expected) {
		return result, errors.New("actual SCEP signer/client key differs")
	}
	original, e := scep.ParsePKIMessage(request.Raw, scep.WithCACerts([]*x509.Certificate{signer}))
	if e != nil || (original.MessageType != scep.PKCSReq && original.MessageType != scep.RenewalReq) || len(original.SenderNonce) != 16 || original.TransactionID != request.TransactionID || !bytes.Equal(original.SenderNonce, request.SenderNonce) {
		return result, errors.New("actual SCEP request signature/context invalid")
	}
	reply, e := scep.ParsePKIMessage(raw, scep.WithCACerts([]*x509.Certificate{ra}))
	if e != nil || reply.MessageType != scep.CertRep || reply.CertRepMessage == nil || reply.TransactionID != original.TransactionID || !bytes.Equal(reply.RecipientNonce, original.SenderNonce) {
		return result, errors.New("SCEP response signer/transaction/nonce invalid")
	}
	result.Status = reply.PKIStatus
	result.SignatureVerified = true
	result.TransactionBound = true
	switch reply.PKIStatus {
	case scep.FAILURE:
		switch reply.FailInfo {
		case scep.BadAlg, scep.BadMessageCheck, scep.BadRequest, scep.BadTime, scep.BadCertID:
			result.FailCode = reply.FailInfo
			return result, nil
		default:
			return scepObservation{}, errors.New("unsupported signed SCEP failure")
		}
	case scep.SUCCESS:
	default:
		return scepObservation{}, errors.New("unsupported pending SCEP response")
	}
	if e := reply.DecryptPKIEnvelope(signer, key); e != nil {
		return scepObservation{}, errors.New("actual SCEP client envelope decryption failed")
	}
	leaf := reply.Certificate
	if leaf == nil || leaf.IsCA || leaf.SerialNumber.Sign() <= 0 || leaf.Subject.CommonName != "cloud-8021x-inventory" || len(leaf.Subject.OrganizationalUnit) != 1 || leaf.Subject.OrganizationalUnit[0] != "task11-renewal-continuity" || leaf.KeyUsage != (x509.KeyUsageDigitalSignature|x509.KeyUsageKeyEncipherment) || len(leaf.ExtKeyUsage) != 1 || leaf.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth || len(leaf.UnknownExtKeyUsage) != 0 || len(leaf.DNSNames)+len(leaf.IPAddresses)+len(leaf.EmailAddresses)+len(leaf.URIs) != 0 || !bytes.Equal(leaf.RawIssuer, intermediate.RawSubject) {
		return scepObservation{}, errors.New("actual SCEP inventory client constraints differ")
	}
	issued, e := x509.MarshalPKIXPublicKey(leaf.PublicKey)
	if e != nil || !bytes.Equal(public, issued) || (original.MessageType == scep.RenewalReq && bytes.Equal(leaf.Raw, signer.Raw)) {
		return scepObservation{}, errors.New("actual issued/renewed client key or certificate differs")
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)
	intermediates := x509.NewCertPool()
	intermediates.AddCert(intermediate)
	if _, e := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); e != nil {
		return scepObservation{}, errors.New("issued SCEP leaf chain invalid")
	}
	result.Leaf = leaf
	result.ChainVerified = true
	return result, nil
}
func makeBrokerRequest(p caClientPlan, token []byte, now time.Time) (*http.Request, error) {
	if validateCAClientPlan(p) != nil || len(token) < 32 || len(token) > 4096 || strings.ContainsAny(string(token), "\x00\r\n") || digestBytes(token) != p.BrokerTokenSHA256 || now.IsZero() {
		return nil, errors.New("pinned original broker request inputs required")
	}
	type webhook struct {
		WebhookEvent   string `json:"webhookEvent"`
		ID             int    `json:"id"`
		EventTimestamp int64  `json:"eventTimestamp"`
		Name           string `json:"name"`
	}
	type event struct {
		SCEPServerURL     string   `json:"scepServerUrl"`
		PayloadIdentifier string   `json:"payloadIdentifier"`
		PayloadTypes      []string `json:"payloadTypes"`
	}
	body, e := json.Marshal(struct {
		Webhook webhook `json:"webhook"`
		Event   event   `json:"event"`
	}{Webhook: webhook{"SCEPChallenge", 1, now.Unix(), "SCEPChallenge"}, Event: event{"https://" + net.JoinHostPort(p.DNS, "8444") + "/scep/wifi-scep", "task11-synthetic-client", []string{"com.apple.security.scep"}}})
	if e != nil {
		return nil, errors.New("broker request encoding failed")
	}
	request, e := http.NewRequest(http.MethodPost, "https://localhost:9081/fleet/scep-challenge", bytes.NewReader(body))
	if e != nil {
		return nil, e
	}
	request.Header.Set("Content-Type", "application/json")
	request.SetBasicAuth("fleet", string(token))
	return request, nil
}
func makeSCEPOperation(p caClientPlan, raw []byte) (*http.Request, error) {
	if validateCAClientPlan(p) != nil || len(raw) == 0 || len(raw) > 32<<10 {
		return nil, errors.New("bounded original SCEP operation required")
	}
	msg, e := scep.ParsePKIMessage(raw)
	if e != nil || (msg.MessageType != scep.PKCSReq && msg.MessageType != scep.RenewalReq) {
		return nil, errors.New("genuine signed SCEP CSR operation required")
	}
	request, e := http.NewRequest(http.MethodPost, "https://"+net.JoinHostPort(p.DNS, "8444")+"/scep/wifi-scep?operation=PKIOperation", bytes.NewReader(bytes.Clone(raw)))
	if e != nil {
		return nil, e
	}
	request.Header.Set("Content-Type", "application/x-pki-message")
	return request, nil
}
