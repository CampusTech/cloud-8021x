package host

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"regexp"
	"strings"
)

const credentialCachePath = transactionRoot + "/active-credentials.json"
const credentialMarkerPath = "/run/cloud-8021x-root/credential-set.json"

type credentialCache struct {
	Reference string            `json:"reference"`
	Bindings  map[string]string `json:"bindings"`
	Files     []File            `json:"files"`
}
type credentialMarker struct{ Reference, SHA256 string }

func digestBytes(data []byte) string { sum := sha256.Sum256(data); return hex.EncodeToString(sum[:]) }
func decodeCredentialCache(data []byte, layout []File) (credentialCache, error) {
	var c credentialCache
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if len(data) > 4<<20 || d.Decode(&c) != nil || d.Decode(new(any)) != io.EOF || !regexp.MustCompile(`^[0-9a-f]{32}$`).MatchString(c.Reference) {
		return c, errors.New("protected credential cache rejected")
	}
	expected := map[string]File{}
	for _, f := range layout {
		if !strings.HasPrefix(f.Path, "/run/cloud-8021x") || f.Path == credentialMarkerPath || !AllowedFile(f.Path) || f.Mode != 0600 {
			return c, errors.New("credential layout rejected")
		}
		if _, exists := expected[f.Path]; exists {
			return c, errors.New("duplicate credential layout")
		}
		expected[f.Path] = f
	}
	if len(c.Files) != len(expected) || len(c.Files) == 0 {
		return c, errors.New("credential set incomplete")
	}
	for _, f := range c.Files {
		want, ok := expected[f.Path]
		if !ok || f.UID != want.UID || f.GID != want.GID || f.Mode != want.Mode || len(f.Data) == 0 || len(f.Data) > 1<<20 {
			return c, errors.New("credential identity rejected")
		}
		delete(expected, f.Path)
	}
	if len(expected) != 0 || len(c.Bindings) < 3 || len(c.Bindings) > 32 {
		return c, errors.New("credential binding incomplete")
	}
	for p, h := range c.Bindings {
		if (p != "/usr/local/bin/cloud-8021x" && p != "/etc/cloud-8021x/config.yaml" && !strings.HasPrefix(p, radiusDirectory+"/")) || !AllowedFile(p) || !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(h) {
			return c, errors.New("credential binding rejected")
		}
	}
	for _, p := range []string{"/usr/local/bin/cloud-8021x", "/etc/cloud-8021x/config.yaml", radiusDirectory + "/radiusd.conf"} {
		if c.Bindings[p] == "" {
			return c, errors.New("required credential binding missing")
		}
	}
	return c, nil
}

// CredentialCacheFiles binds the entire staged credential set to the exact
// executable, config and native tree. Only root-local receipt/cache files contain
// credential bytes; the PG installation journal holds the opaque reference alone.
func (t *Transaction) CredentialCacheFiles(files []File, tree map[string][]byte) ([]File, error) {
	c := credentialCache{Reference: t.Reference(), Bindings: map[string]string{}}
	for _, f := range files {
		if strings.HasPrefix(f.Path, "/run/cloud-8021x") {
			c.Files = append(c.Files, f)
		}
	}
	for _, p := range []string{"/usr/local/bin/cloud-8021x", "/etc/cloud-8021x/config.yaml"} {
		found := false
		for _, f := range files {
			if f.Path == p {
				c.Bindings[p] = digestBytes(f.Data)
				found = true
				break
			}
		}
		if !found {
			h, e := installedHash(p, 256<<20)
			if e != nil {
				return nil, e
			}
			c.Bindings[p] = h
		}
	}
	for p, data := range tree {
		c.Bindings[radiusDirectory+"/"+p] = digestBytes(data)
	}
	data, e := json.Marshal(c)
	if e != nil {
		return nil, e
	}
	if _, e = decodeCredentialCache(data, c.Files); e != nil {
		return nil, e
	}
	marker, e := json.Marshal(credentialMarker{c.Reference, digestBytes(data)})
	if e != nil {
		return nil, e
	}
	return []File{{Path: credentialCachePath, Data: data, Mode: 0600}, {Path: credentialMarkerPath, Data: marker, Mode: 0600}}, nil
}
func readPrivateCache(path string, maximum int64) ([]byte, error) {
	f, e := rootFile(path, maximum)
	if e != nil {
		return nil, e
	}
	defer func() { _ = f.Close() }()
	st, e := f.Stat()
	if e != nil || st.Mode().Perm() != 0600 {
		return nil, errors.New("private cache mode rejected")
	}
	return io.ReadAll(f)
}
func loadCredentialCache(layout []File) (credentialCache, []byte, error) {
	data, e := readPrivateCache(credentialCachePath, 4<<20)
	if e != nil {
		return credentialCache{}, nil, e
	}
	c, e := decodeCredentialCache(data, layout)
	if e != nil {
		return c, nil, e
	}
	for p, want := range c.Bindings {
		got, e := installedHash(p, 256<<20)
		if e != nil || got != want {
			return c, nil, errors.New("credential cache differs from installed binary/config/native state")
		}
	}
	return c, data, nil
}
func committedCredentialCache(layout []File) (credentialCache, []byte, error) {
	c, data, e := loadCredentialCache(layout)
	if e != nil {
		return c, nil, e
	}
	current, e := readPrivateCache(transactionRoot+"/current.json", 4096)
	if e != nil {
		return c, nil, e
	}
	var generation installedGeneration
	d := json.NewDecoder(bytes.NewReader(current))
	d.DisallowUnknownFields()
	if d.Decode(&generation) != nil || d.Decode(new(any)) != io.EOF || generation.Reference != c.Reference || generation.ApplicationSHA256 != c.Bindings["/usr/local/bin/cloud-8021x"] || generation.ConfigSHA256 != c.Bindings["/etc/cloud-8021x/config.yaml"] {
		return c, nil, errors.New("credential cache is not the completed installation")
	}
	return c, data, nil
}

// CommittedCredentials is used by certificate renewal: unrelated credentials
// remain pinned to the completed set and are never refreshed from latest secrets.
func CommittedCredentials(layout []File) (map[string][]byte, error) {
	c, _, e := committedCredentialCache(layout)
	if e != nil {
		return nil, e
	}
	values := map[string][]byte{}
	for _, f := range c.Files {
		values[f.Path] = append([]byte(nil), f.Data...)
	}
	return values, nil
}

// RestoreBootCredentials never contacts PG/Secret Manager. An existing volatile
// marker permits only verification of the already-staged set during activation.
// After reboot the marker is gone, so restoration requires a completed generation.
func RestoreBootCredentials(layout []File) error {
	if os.Geteuid() != 0 {
		return errors.New("credential restore requires root")
	}
	marker, e := readPrivateCache(credentialMarkerPath, 4096)
	if e == nil {
		c, data, e := loadCredentialCache(layout)
		if e != nil {
			return e
		}
		var m credentialMarker
		d := json.NewDecoder(bytes.NewReader(marker))
		d.DisallowUnknownFields()
		if d.Decode(&m) != nil || d.Decode(new(any)) != io.EOF || m.Reference != c.Reference || m.SHA256 != digestBytes(data) {
			return errors.New("active credential marker rejected")
		}
		for _, f := range c.Files {
			saved, e := Snapshot(f)
			if e != nil || !saved.Exists || saved.UID != f.UID || saved.GID != f.GID || saved.Mode != f.Mode || !bytes.Equal(saved.Data, f.Data) {
				return errors.New("active credential set differs; gated bootstrap required")
			}
		}
		return nil
	}
	if !errors.Is(e, os.ErrNotExist) {
		return e
	}
	c, data, e := committedCredentialCache(layout)
	if e != nil {
		return e
	}
	encoded, e := json.Marshal(credentialMarker{c.Reference, digestBytes(data)})
	if e != nil {
		return e
	}
	files := append(append([]File(nil), c.Files...), File{Path: credentialMarkerPath, Data: encoded, Mode: 0600})
	var saved []SavedFile
	for _, f := range files {
		old, e := Snapshot(f)
		if e != nil {
			return e
		}
		saved = append(saved, old)
	}
	for i, f := range files {
		if e := Write(f); e != nil {
			for j := i; j >= 0; j-- {
				e = errors.Join(e, Restore(saved[j]))
			}
			return e
		}
	}
	return nil
}
