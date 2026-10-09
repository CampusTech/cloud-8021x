package main

import (
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
)

func secretRequest(t *testing.T, f *fixture, method, path, body string, want int, peers ...string) map[string]any {
	t.Helper()
	r := httptest.NewRequest(method, "https://secretmanager.googleapis.com/v1/projects/task11-fixture/secrets/"+path, strings.NewReader(body))
	if len(peers) > 0 {
		r.RemoteAddr = peers[0] + ":4321"
	}
	r.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	f.ServeHTTP(w, r)
	if w.Code != want {
		t.Fatalf("%s %s: status %d, want %d: %s", method, path, w.Code, want, w.Body.String())
	}
	var out map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	return out
}
func TestSecretPublicationImmutableCRCAndLatest(t *testing.T) {
	f := testFixture(t)
	f.phase = "active"
	const name = "radius-smallstep-server-cert"
	f.config.Secrets["projects/111222333444/secrets/"+name] = map[string]string{"9": base64.StdEncoding.EncodeToString([]byte("original"))}
	payload := `{"payload":{"data":"bmV3","dataCrc32c":"` + crcString([]byte("new")) + `"}}`
	added := secretRequest(t, f, "POST", name+":addVersion", payload, 200)
	if added["name"] != "projects/111222333444/secrets/"+name+"/versions/10" {
		t.Fatal("version allocation must be monotonic and canonical")
	}
	secretRequest(t, f, "POST", name+":addVersion", `{"payload":{"data":"ZXZpbA==","dataCrc32c":"0"}}`, 400)
	secretRequest(t, f, "POST", "smallstep-ca-cert:addVersion", payload, 404)
	versions := secretRequest(t, f, "GET", name+"/versions?filter=state%3DENABLED&pageSize=100", "", 200)["versions"].([]any)
	if len(versions) != 2 || versions[0].(map[string]any)["name"] != added["name"] {
		t.Fatal("enabled versions must be newest-first; rejected CRC must not mutate")
	}
	for version, expected := range map[string]string{"9": "original", "10": "new"} {
		value := secretRequest(t, f, "GET", name+"/versions/"+version+":access", "", 200)["payload"].(map[string]any)
		if value["data"] != base64.StdEncoding.EncodeToString([]byte(expected)) || value["dataCrc32c"] != crcString([]byte(expected)) {
			t.Fatal("immutable payload/CRC changed")
		}
	}
	f.phase = "passive"
	secretRequest(t, f, "POST", name+":addVersion", payload, 403)
}
