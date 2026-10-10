package main

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/CampusTech/cloud-8021x/tests/runtime/task11-acceptance/scenariocontract"
	"github.com/smallstep/scep"
)

func pureECExecutionInput(t *testing.T) (decodedNASInput, map[string][]byte, pureECChain) {
	t.Helper()
	f := pureECFixture(t)
	p := pureNASPlan()
	p.Scenario.Scenario = "ca-continuity"
	p.Scenario.Case = "ca-ec-continuity"
	p.EC = ecClientPlan{Phase: "original", Peer: "10.203.11.31", DNS: "ec.task11.test", RootSHA256: digestBytes(f.rootPEM), IntermediateSHA256: digestBytes(f.intermediatePEM), ClientCertificateSHA256: digestBytes(f.clientPEM), ClientKeySHA256: digestBytes(f.keyPEM)}
	p.Materials["ec-root.pem"] = p.EC.RootSHA256
	p.Materials["ec-intermediate.pem"] = p.EC.IntermediateSHA256
	p.Materials["client.pem"] = p.EC.ClientCertificateSHA256
	p.Materials["client.key"] = p.EC.ClientKeySHA256
	input := decodedNASInput{Plan: p, Request: scenariocontract.Request{Schema: 1, Action: "nas-ca-original", Authority: "ec"}}
	return input, map[string][]byte{"ec-root.pem": f.rootPEM, "ec-intermediate.pem": f.intermediatePEM, "client.pem": f.clientPEM, "client.key": f.keyPEM}, f
}
func TestECExecutionUsesRealMTLSRouteAndActualSignedRenewedDER(t *testing.T) {
	input, materials, f := pureECExecutionInput(t)
	execution, e := prepareCAExecution(input, materials, f.now)
	if e != nil {
		t.Fatal(e)
	}
	transport, ok := execution.authorityClient.Transport.(*http.Transport)
	if !ok || transport.TLSClientConfig == nil || len(transport.TLSClientConfig.Certificates) != 1 {
		t.Fatal("fixed original mTLS client missing")
	}
	reply, e := json.Marshal(ecRenewReply{Certificate: string(pemCertificate(f.renewed)), CA: string(f.intermediatePEM), Chain: []string{string(pemCertificate(f.renewed)), string(f.intermediatePEM)}})
	if e != nil {
		t.Fatal(e)
	}
	called := false
	execution.authorityClient.Transport = pureRoundTrip(func(request *http.Request) (*http.Response, error) {
		called = true
		if request.Method != "POST" || request.URL.String() != "https://ec.task11.test:8443/renew" || request.Header.Get("Authorization") != "" {
			t.Fatal("EC route gained JWT/CSR/endpoint override")
		}
		return &http.Response{StatusCode: 201, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(bytes.NewReader(reply))}, nil
	})
	result, e := executeCA(context.Background(), execution)
	if e != nil {
		t.Fatal(e)
	}
	if !called || result.Authority != "ec" || result.Route != "ec-legacy-mtls-renew" || result.Phase != "original" || result.Peer != "10.203.11.31" || result.Issued == nil || !bytes.Equal(result.Issued.LeafDER, f.renewed.Raw) || !result.Response.SignatureVerified || !result.Response.ChainVerified || !result.Response.TransactionBound {
		t.Fatal("actual renewed DER/chain observation missing")
	}
	input.Request.Action = "nas-ca-passive"
	execution, e = prepareCAExecution(input, materials, f.now)
	if e != nil {
		t.Fatal(e)
	}
	execution.authorityClient.Transport = pureRoundTrip(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 503, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("unavailable"))}, nil
	})
	result, e = executeCA(context.Background(), execution)
	if e != nil || result.Issued != nil || result.Response.HTTPStatus != 503 || result.Peer != "10.203.11.21" {
		t.Fatal("passive failed response became issuance or wrong peer")
	}
}
func TestRSAExecutionUsesGenuineBrokerChallengeAndSignedSDKExchange(t *testing.T) {
	f := purePriorNASInput(t)
	input, e := decodeNASInput(encodePureNASInput(t, f.input))
	if e != nil {
		t.Fatal(e)
	}
	// Prepare actual adopted client from independently selected old DER. The
	// in-memory response below uses a test authority; no actual CA/socket runs.
	chain := pureSCEPFixture(t)
	// RSA original test uses its genuine persistent client/RA fixture, with its
	// own separately pinned immutable material. Renewal path is tested below.
	original := pureNASPlan()
	original.Scenario.Scenario = "ca-continuity"
	original.Scenario.Case = "ca-rsa-continuity"
	cert := func(c *x509.Certificate) []byte { return pemCertificate(c) }
	keyDER, e := x509.MarshalPKCS8PrivateKey(chain.clientKey)
	if e != nil {
		t.Fatal(e)
	}
	keyPEM := pemPrivateKey(keyDER)
	token := []byte(strings.Repeat("task11-broker-", 4))
	// A proper loopback TLS cert is supplied by the exact earlier client fixture.
	loopback := pureTrustPEM(t, false, "localhost")
	original.RSA.RootSHA256 = digestBytes(cert(chain.root))
	original.RSA.IntermediateSHA256 = digestBytes(cert(chain.intermediate))
	original.RSA.DecrypterSHA256 = digestBytes(cert(chain.decrypter))
	original.RSA.BrokerCertificateSHA256 = digestBytes(loopback)
	original.RSA.BrokerTokenSHA256 = digestBytes(token)
	original.Materials["scep-client.key"] = digestBytes(keyPEM)
	material := map[string][]byte{"rsa-root.pem": cert(chain.root), "rsa-intermediate.pem": cert(chain.intermediate), "rsa-decrypter.pem": cert(chain.decrypter), "scep-client.key": keyPEM, "broker.crt": loopback, "broker-token": token}
	originalInput := decodedNASInput{Plan: original, Request: scenariocontract.Request{Action: "nas-ca-original", Authority: "rsa"}}
	execution, e := prepareCAExecution(originalInput, material, chain.now)
	if e != nil {
		t.Fatal(e)
	}
	brokerCalled, caCalled := false, false
	execution.brokerClient.Transport = pureRoundTrip(func(request *http.Request) (*http.Response, error) {
		brokerCalled = true
		user, password, ok := request.BasicAuth()
		if !ok || user != "fleet" || password != string(token) || request.URL.String() != "https://localhost:9081/fleet/scep-challenge" {
			t.Fatal("fixed broker credential/route missing")
		}
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"text/plain; charset=utf-8"}}, Body: io.NopCloser(strings.NewReader("opaque-real-authority-validates-challenge"))}, nil
	})
	execution.authorityClient.Transport = pureRoundTrip(func(request *http.Request) (*http.Response, error) {
		caCalled = true
		if !brokerCalled || request.URL.String() != "https://rsa.task11.test:8444/scep/wifi-scep?operation=PKIOperation" {
			t.Fatal("SCEP preceded broker or changed route")
		}
		raw, e := io.ReadAll(request.Body)
		if e != nil {
			t.Fatal(e)
		}
		message, e := scep.ParsePKIMessage(raw)
		if e != nil {
			t.Fatal(e)
		}
		if e = message.DecryptPKIEnvelope(chain.decrypter, chain.decrypterKey); e != nil {
			t.Fatal(e)
		}
		reply, e := message.Success(chain.decrypter, chain.decrypterKey, chain.issued)
		if e != nil {
			t.Fatal(e)
		}
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"application/x-pki-message"}}, Body: io.NopCloser(bytes.NewReader(reply.Raw))}, nil
	})
	result, e := executeCA(context.Background(), execution)
	if e != nil || !caCalled || result.Issued == nil || !bytes.Equal(result.Issued.LeafDER, chain.issued.Raw) {
		t.Fatal("genuine SDK reply/client signer/chain not observed")
	}
	// Existing selected original result must be the renewal signer, with no
	// initial request fallback. Preparation alone has no HTTP side effect.
	material = map[string][]byte{"rsa-root.pem": f.root, "rsa-intermediate.pem": f.intermediate, "rsa-decrypter.pem": f.decrypter, "scep-client.key": f.key}
	input.Plan.RSA.BrokerCertificateSHA256 = digestBytes(loopback)
	input.Plan.RSA.BrokerTokenSHA256 = digestBytes(token)
	material["broker.crt"] = loopback
	material["broker-token"] = token
	execution, e = prepareCAExecution(input, material, f.now)
	if e != nil {
		t.Fatal(e)
	}
	if execution.signer == nil || !bytes.Equal(execution.signer.Raw, f.leaf.Raw) || execution.peer != "10.203.11.21" {
		t.Fatal("adopted signer was replaced with initial self-signed credential")
	}
}

func pemCertificate(c *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
}
func pemPrivateKey(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}
