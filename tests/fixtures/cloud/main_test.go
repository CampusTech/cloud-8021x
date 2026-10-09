package main

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
)

const testKey = "projects/111222333444/locations/us-central1/keyRings/fixture/cryptoKeys/ec/cryptoKeyVersions/1"

func testFixture(t *testing.T) *fixture {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &fixture{config: seed{Schema: 1, ProjectID: "task11-fixture", ProjectNumber: "111222333444", Secrets: map[string]map[string]string{"projects/111222333444/secrets/example": {"7": base64.StdEncoding.EncodeToString([]byte("synthetic"))}}}, keys: map[string]crypto.Signer{testKey: key}, phase: "passive", journal: &bytes.Buffer{}}
}
func TestRESTPassiveAuthorityAndSecretChecksums(t *testing.T) {
	f := testFixture(t)
	for _, tc := range []struct {
		method, target string
		status         int
	}{
		{"GET", "https://secretmanager.googleapis.com/v1/projects/task11-fixture/secrets/example/versions/7:access", 200},
		{"GET", "https://secretmanager.googleapis.com/v1/projects/wrong-project/secrets/example/versions/7:access", 404},
		{"POST", "https://secretmanager.googleapis.com/v1/projects/task11-fixture/secrets/example:addVersion", 404},
		{"POST", "https://fleet.fixture/anything", 404},
	} {
		r := httptest.NewRequest(tc.method, tc.target, nil)
		r.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		f.ServeHTTP(w, r)
		if w.Code != tc.status {
			t.Fatalf("%s: %d", tc.target, w.Code)
		}
		if tc.status == 200 {

			var data map[string]any
			if err := json.Unmarshal(w.Body.Bytes(), &data); err != nil {
				t.Fatal(err)
			}
			payload := data["payload"].(map[string]any)
			if payload["dataCrc32c"] != crcString([]byte("synthetic")) {
				t.Fatal("bad payload CRC")
			}
		}
	}
	if strings.Contains(f.journal.(*bytes.Buffer).String(), token) {
		t.Fatal("bearer leaked into journal")
	}
}
func TestRealSignRequiresActiveAndCorrectDigestCRC(t *testing.T) {
	f := testFixture(t)
	digest := sha256.Sum256([]byte("synthetic message"))
	if _, err := f.sign(testKey, digest[:], crcString(digest[:])); err == nil {
		t.Fatal("passive sign succeeded")
	}
	f.phase = "active"
	if _, err := f.sign(testKey, digest[:], "0"); err == nil {
		t.Fatal("wrong checksum succeeded")
	}
	signature, err := f.sign(testKey, digest[:], crcString(digest[:]))
	if err != nil {
		t.Fatal(err)
	}
	if !ecdsa.VerifyASN1(f.keys[testKey].Public().(*ecdsa.PublicKey), digest[:], signature) {
		t.Fatal("fixture signature does not verify")
	}
}
func TestGRPCStrictWireAndPassiveRefusal(t *testing.T) {
	f := testFixture(t)
	name := bytesField(nil, 1, []byte(testKey))
	if _, err := f.grpcCall(kmsService+"GetPublicKey", name); err != nil {
		t.Fatal(err)
	}
	if _, err := f.grpcCall(kmsService+"GetPublicKey", append(name, name...)); err == nil {
		t.Fatal("duplicate name accepted")
	}
	digest := sha256.Sum256([]byte("synthetic"))
	request := bytesField(name, 3, bytesField(nil, 1, digest[:]))
	if _, err := f.grpcCall(kmsService+"AsymmetricSign", request); err == nil {
		t.Fatal("passive grpc sign accepted")
	}
	f.phase = "active"
	if _, err := f.grpcCall(kmsService+"AsymmetricSign", request); err != nil {
		t.Fatal(err)
	}
	if _, err := f.grpcCall(kmsService+"Decrypt", name); err == nil {
		t.Fatal("unlisted RPC accepted")
	}
}
func TestMetadataAndMutationRoutesDenyByDefault(t *testing.T) {
	f := testFixture(t)
	r := httptest.NewRequest("GET", "http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token", nil)
	w := httptest.NewRecorder()
	f.ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatal("metadata header ignored")
	}
	r.Header.Set("Metadata-Flavor", "Google")
	w = httptest.NewRecorder()
	f.ServeHTTP(w, r)
	if w.Code != 200 || w.Header().Get("Metadata-Flavor") != "Google" {
		t.Fatal("metadata token contract")
	}
	f.config.Routes = []route{{Host: "fleet.fixture", Method: "POST", Target: "/exact", Mutation: true, Status: 200, Response: json.RawMessage(`{}`)}}
	r = httptest.NewRequest("POST", "https://fleet.fixture/exact", nil)
	w = httptest.NewRecorder()
	f.ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatal("passive provider write permitted")
	}
}

func TestMetadataExactStepCAScopedTokenURI(t *testing.T) {
	const path = "/computeMetadata/v1/instance/service-accounts/default/token"
	const scopes = "https%3A%2F%2Fwww.googleapis.com%2Fauth%2Fcloud-platform%2Chttps%3A%2F%2Fwww.googleapis.com%2Fauth%2Fcloudkms"
	for _, phase := range []string{"passive", "active"} {
		for _, tc := range []struct {
			name, query, flavor string
			status              int
		}{
			{"actual SDK scopes", "?scopes=" + scopes, "Google", 200},
			{"missing required header", "?scopes=" + scopes, "", 403},
			{"extra query parameter", "?scopes=" + scopes + "&unlisted=1", "Google", 404},
			{"duplicated scopes parameter", "?scopes=" + scopes + "&scopes=" + scopes, "Google", 404},
			{"unrecognized scope", "?scopes=https%3A%2F%2Fwww.googleapis.com%2Fauth%2Fcompute", "Google", 404},
			{"extra scope", "?scopes=" + scopes + "%2Chttps%3A%2F%2Fwww.googleapis.com%2Fauth%2Fcompute", "Google", 404},
			{"unrecognized query", "?scope=" + scopes, "Google", 404},
		} {
			t.Run(phase+"/"+tc.name, func(t *testing.T) {
				f := testFixture(t)
				f.phase = phase
				r := httptest.NewRequest("GET", "http://169.254.169.254"+path+tc.query, nil)
				r.Header.Set("Metadata-Flavor", tc.flavor)
				w := httptest.NewRecorder()
				f.ServeHTTP(w, r)
				if w.Code != tc.status || w.Header().Get("Metadata-Flavor") != "Google" {
					t.Fatalf("status/header: %d %v", w.Code, w.Header())
				}
				if tc.status == 200 {
					var response struct {
						AccessToken string `json:"access_token"`
						ExpiresIn   int    `json:"expires_in"`
						TokenType   string `json:"token_type"`
					}
					if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
						t.Fatal(err)
					}
					if response.AccessToken != token || response.ExpiresIn != 3600 || response.TokenType != "Bearer" {
						t.Fatal("scoped synthetic token response changed")
					}
				}
				var receipt struct {
					Target string `json:"target"`
					Phase  string `json:"phase"`
					Status int    `json:"status"`
				}
				journal := f.journal.(*bytes.Buffer).Bytes()
				if err := json.Unmarshal(journal, &receipt); err != nil {
					t.Fatal(err)
				}
				if receipt.Target != "169.254.169.254"+path+tc.query || receipt.Phase != phase || receipt.Status != tc.status || bytes.Contains(journal, []byte(token)) {
					t.Fatal("metadata receipt changed or exposed token")
				}
			})
		}
	}
}
