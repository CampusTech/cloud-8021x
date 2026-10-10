package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/smallstep/scep"
)

type pureSCEPExchange struct {
	request                                       *scep.PKIMessage
	signer, decrypter, issued, root, intermediate *x509.Certificate
	clientKey, decrypterKey                       *rsa.PrivateKey
	intermediateKey                               *ecdsa.PrivateKey
	raw                                           []byte
	now                                           time.Time
}

func pureSCEPFixture(t *testing.T) pureSCEPExchange {
	t.Helper()
	decrypter, decrypterKey := pureClientCredential(t, "pure pinned SCEP RA")
	signer, clientKey := pureClientCredential(t, "task11-scep-client")
	request, e := makeSCEPRequest(clientKey, signer, decrypter, "test-only-genuine-wire-challenge", false)
	if e != nil {
		t.Fatal(e)
	}
	parsed, e := scep.ParsePKIMessage(request.Raw)
	if e != nil {
		t.Fatal(e)
	}
	if e = parsed.DecryptPKIEnvelope(decrypter, decrypterKey); e != nil {
		t.Fatal(e)
	}
	chain := pureECFixture(t)
	template := &x509.Certificate{SerialNumber: big.NewInt(27), Subject: pkix.Name{CommonName: "cloud-8021x-inventory", OrganizationalUnit: []string{"task11-renewal-continuity"}}, NotBefore: chain.now.Add(-time.Minute), NotAfter: chain.now.Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, BasicConstraintsValid: true}
	der, e := x509.CreateCertificate(rand.Reader, template, chain.intermediate, &clientKey.PublicKey, chain.intermediateKey)
	if e != nil {
		t.Fatal(e)
	}
	leaf, e := x509.ParseCertificate(der)
	if e != nil {
		t.Fatal(e)
	}
	reply, e := parsed.Success(decrypter, decrypterKey, leaf)
	if e != nil {
		t.Fatal(e)
	}
	return pureSCEPExchange{intermediateKey: chain.intermediateKey, request: request, signer: signer, decrypter: decrypter, issued: leaf, root: chain.root, intermediate: chain.intermediate, clientKey: clientKey, decrypterKey: decrypterKey, raw: reply.Raw, now: chain.now}
}
func (f pureSCEPExchange) reply(t *testing.T, mutate func(*scep.PKIMessage), leaf *x509.Certificate, fail bool) []byte {
	t.Helper()
	msg, e := scep.ParsePKIMessage(f.request.Raw)
	if e != nil {
		t.Fatal(e)
	}
	if e = msg.DecryptPKIEnvelope(f.decrypter, f.decrypterKey); e != nil {
		t.Fatal(e)
	}
	mutate(msg)
	var r *scep.PKIMessage
	if fail {
		r, e = msg.Fail(f.decrypter, f.decrypterKey, scep.BadRequest)
	} else {
		r, e = msg.Success(f.decrypter, f.decrypterKey, leaf)
	}
	if e != nil {
		t.Fatal(e)
	}
	return r.Raw
}
func TestSCEPReplyBoundToActualTransactionNonceSignerAndClientKey(t *testing.T) {
	f := pureSCEPFixture(t)
	observed, e := verifySCEPReply(f.raw, f.request, f.signer, f.clientKey, f.decrypter, f.root, f.intermediate, f.now)
	if e != nil {
		t.Fatal(e)
	}
	if observed.Leaf == nil || !bytes.Equal(observed.Leaf.Raw, f.issued.Raw) || observed.Status != scep.SUCCESS || !observed.SignatureVerified || !observed.TransactionBound || !observed.ChainVerified {
		t.Fatal("actual issued leaf/cryptographic proofs lost")
	}
	for _, kind := range []string{"tamper", "transaction", "nonce", "foreign-ra", "foreign-chain", "wrong-client-key", "wrong-leaf-key", "wrong-subject", "server-auth", "unexpected-san", "oversized"} {
		t.Run(kind, func(t *testing.T) {
			raw := bytes.Clone(f.raw)
			ra, root, intermediate := f.decrypter, f.root, f.intermediate
			key := f.clientKey
			switch kind {
			case "tamper":
				raw[len(raw)-1] ^= 1
			case "transaction":
				raw = f.reply(t, func(m *scep.PKIMessage) { m.TransactionID = "foreign-transaction" }, f.issued, false)
			case "nonce":
				raw = f.reply(t, func(m *scep.PKIMessage) { m.SenderNonce = []byte("foreign-nonce") }, f.issued, false)
			case "foreign-ra":
				ra, _ = pureClientCredential(t, "foreign RA")
			case "foreign-chain":
				other := pureECFixture(t)
				root, intermediate = other.root, other.intermediate
			case "wrong-client-key":
				_, key = pureClientCredential(t, "foreign client")
			case "wrong-leaf-key", "wrong-subject", "server-auth", "unexpected-san":
				template := *f.issued
				public := f.issued.PublicKey
				switch kind {
				case "wrong-leaf-key":
					_, foreign := pureClientCredential(t, "foreign issued key")
					public = &foreign.PublicKey
				case "wrong-subject":
					template.Subject = pkix.Name{CommonName: "foreign-identity"}
					template.RawSubject = nil
				case "server-auth":
					template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
				case "unexpected-san":
					template.DNSNames = []string{"unexpected.task11.test"}
				}
				der, err := x509.CreateCertificate(rand.Reader, &template, f.intermediate, public, f.intermediateKey)
				if err != nil {
					t.Fatal(err)
				}
				leaf, err := x509.ParseCertificate(der)
				if err != nil {
					t.Fatal(err)
				}
				raw = f.reply(t, func(*scep.PKIMessage) {}, leaf, false)
			case "oversized":
				raw = bytes.Repeat([]byte("x"), 32769)
			}
			if _, e := verifySCEPReply(raw, f.request, f.signer, key, ra, root, intermediate, f.now); e == nil {
				t.Fatal("unbound/forged/foreign SCEP reply accepted")
			}
		})
	}
}
func TestSignedSCEPFailureHasNoFabricatedIssuedLeaf(t *testing.T) {
	f := pureSCEPFixture(t)
	raw := f.reply(t, func(*scep.PKIMessage) {}, nil, true)
	observed, e := verifySCEPReply(raw, f.request, f.signer, f.clientKey, f.decrypter, f.root, f.intermediate, f.now)
	if e != nil {
		t.Fatal(e)
	}
	if observed.Leaf != nil || observed.Status != scep.FAILURE || observed.FailCode == "" || !observed.SignatureVerified || !observed.TransactionBound || observed.ChainVerified {
		t.Fatal("signed denial became issuance/admission")
	}
}
func TestOriginalBrokerAndSCEPRequestsUseExactConfiguredWire(t *testing.T) {
	p := pureNASPlan().RSA
	token := []byte(strings.Repeat("s", 32))
	p.BrokerTokenSHA256 = digestBytes(token)
	now := time.Now().UTC()
	broker, e := makeBrokerRequest(p, token, now)
	if e != nil {
		t.Fatal(e)
	}
	user, password, ok := broker.BasicAuth()
	if !ok || user != "fleet" || password != string(token) || broker.Method != "POST" || broker.URL.String() != "https://localhost:9081/fleet/scep-challenge" || broker.Header.Get("Content-Type") != "application/json" {
		t.Fatal("actual protected broker wire changed")
	}
	body, e := readClientBody(broker.Body, 65536)
	if e != nil {
		t.Fatal(e)
	}
	if e = broker.Body.Close(); e != nil {
		t.Fatal(e)
	}
	var payload struct {
		Webhook struct {
			WebhookEvent   string `json:"webhookEvent"`
			ID             int    `json:"id"`
			EventTimestamp int64  `json:"eventTimestamp"`
			Name           string `json:"name"`
		} `json:"webhook"`
		Event struct {
			SCEPServerURL     string   `json:"scepServerUrl"`
			PayloadIdentifier string   `json:"payloadIdentifier"`
			PayloadTypes      []string `json:"payloadTypes"`
		} `json:"event"`
	}
	if e = json.Unmarshal(body, &payload); e != nil {
		t.Fatal(e)
	}
	if payload.Event.SCEPServerURL != "https://rsa.task11.test:8444/scep/wifi-scep" || payload.Webhook.WebhookEvent != "SCEPChallenge" || len(payload.Event.PayloadTypes) != 1 || payload.Event.PayloadTypes[0] != "com.apple.security.scep" {
		t.Fatal("configured advertised URL/Fleet event mismatch")
	}
	f := pureSCEPFixture(t)
	op, e := makeSCEPOperation(p, f.request.Raw)
	if e != nil {
		t.Fatal(e)
	}
	if op.Method != "POST" || op.URL.String() != "https://rsa.task11.test:8444/scep/wifi-scep?operation=PKIOperation" || op.Header.Get("Content-Type") != "application/x-pki-message" || op.Header.Get("Authorization") != "" {
		t.Fatal("ordinary SCEP operation changed")
	}
	transmitted, e := readClientBody(op.Body, 32768)
	if e != nil {
		t.Fatal(e)
	}
	if e = op.Body.Close(); e != nil {
		t.Fatal(e)
	}
	if !bytes.Equal(transmitted, f.request.Raw) {
		t.Fatal("actual signed/encrypted CSR rewritten")
	}
	bad := bytes.Clone(token)
	bad[0] ^= 1
	if _, e := makeBrokerRequest(p, bad, now); e == nil {
		t.Fatal("untrusted broker token accepted")
	}
	if _, e := makeSCEPOperation(p, bytes.Repeat([]byte("x"), 32769)); e == nil {
		t.Fatal("unbounded operation accepted")
	}
}
