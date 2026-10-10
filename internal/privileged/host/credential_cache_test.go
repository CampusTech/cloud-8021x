package host

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestCredentialCacheRejectsUnboundOrAlteredSets(t *testing.T) {
	files := []File{{Path: "/run/cloud-8021x/credentials/policy", Data: []byte("original-policy-secret"), UID: 1001, GID: 1001, Mode: 0600}}
	bindings := map[string]string{"/usr/local/bin/cloud-8021x": strings.Repeat("a", 64), "/etc/cloud-8021x/config.yaml": strings.Repeat("b", 64), "/etc/freeradius/3.0/radiusd.conf": strings.Repeat("c", 64)}
	cache := credentialCache{Reference: strings.Repeat("d", 32), Files: files, Bindings: bindings}
	data, _ := json.Marshal(cache)
	if _, err := decodeCredentialCache(data, files); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*credentialCache){
		"reference": func(c *credentialCache) { c.Reference = "../other" },
		"missing":   func(c *credentialCache) { c.Files = nil },
		"duplicate": func(c *credentialCache) { c.Files = append(c.Files, c.Files[0]) },
		"owner":     func(c *credentialCache) { c.Files[0].UID = 1002 },
		"outside":   func(c *credentialCache) { c.Files[0].Path = "/etc/shadow" },
		"empty":     func(c *credentialCache) { c.Files[0].Data = nil },
		"binding":   func(c *credentialCache) { delete(c.Bindings, "/etc/cloud-8021x/config.yaml") },
	} {
		t.Run(name, func(t *testing.T) {
			var copy credentialCache
			_ = json.Unmarshal(data, &copy)
			mutate(&copy)
			encoded, _ := json.Marshal(copy)
			if _, err := decodeCredentialCache(encoded, files); err == nil {
				t.Fatal("unsafe cache accepted")
			}
		})
	}
	if _, err := decodeCredentialCache(append(data, []byte(`{}`)...), files); err == nil {
		t.Fatal("trailing object accepted")
	}
}

func TestCredentialTrustBindingVersionIsRequiredForNewDocuments(t *testing.T) {
	files := []File{{Path: "/run/cloud-8021x/credentials/policy", Data: []byte("policy"), UID: 1001, GID: 1001, Mode: 0600}}
	cache := credentialCache{TrustBindingVersion: 1, Reference: strings.Repeat("a", 32), Files: files, Bindings: map[string]string{"/usr/local/bin/cloud-8021x": strings.Repeat("a", 64), "/etc/cloud-8021x/config.yaml": strings.Repeat("b", 64), radiusDirectory + "/radiusd.conf": strings.Repeat("c", 64)}}
	raw, _ := json.Marshal(cache)
	if _, err := decodeCredentialCache(raw, files); err == nil {
		t.Fatal("new credential cache accepts absent database CA binding")
	}
	cache.Bindings[PostgresCAFile] = strings.Repeat("d", 64)
	raw, _ = json.Marshal(cache)
	if _, err := decodeCredentialCache(raw, files); err != nil {
		t.Fatal(err)
	}
	cache.TrustBindingVersion = 2
	raw, _ = json.Marshal(cache)
	if _, err := decodeCredentialCache(raw, files); err == nil {
		t.Fatal("unknown trust binding schema accepted")
	}
}
