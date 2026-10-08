package auth

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type memoryStore struct {
	cursors  map[string]string
	payloads map[string]json.RawMessage
	fail     bool
}

func (s *memoryStore) Cursor(_ context.Context, source string) (string, error) {
	return s.cursors[source], nil
}
func (s *memoryStore) AuthEvent(_ context.Context, source, expected, next, id string, payload json.RawMessage) error {
	if s.fail {
		return errors.New("outage")
	}
	if s.cursors[source] != expected {
		return errors.New("conflict")
	}
	s.cursors[source] = next
	s.payloads[id] = append([]byte(nil), payload...)
	return nil
}

const record = "Thu Oct  8 10:00:00 2026\n\tPacket-Type = Access-Accept\n\tC8021X-Receipt = 1791453600\n\tC8021X-Client = \"office\"\n\tC8021X-Location = \"nyc\"\n\tC8021X-Source = \"2001:db8::1\"\n\tC8021X-Station = \"aa-bb-cc-dd-ee-ff\"\n\tC8021X-Called = \"quote\\\"slash\\\\line\\n\"\n\n"

func TestEscapedGrammarAndIncompleteTail(t *testing.T) {
	legacy := strings.Replace(record, "\n\n", "\n\tTLS-Client-Cert-Valid-Since = \"2026\"\n\tTLS-Client-Cert-X509v3-Extended-Key-Usage-OID = \"1.3.6.1.5.5.7.3.2\"\n\n", 1)
	if _, _, err := Parse([]byte(legacy)); err != nil {
		t.Fatal("public legacy cache metadata blocked retained final event", err)
	}
	r, n, err := Parse([]byte(record))
	if err != nil || n != len(record) || r.Values["C8021X-Called"][0] != "quote\"slash\\line\n" {
		t.Fatalf("%+v %d %v", r, n, err)
	}
	_, n, err = Parse([]byte(record[:len(record)-1]))
	if err != nil || n != 0 {
		t.Fatal("advanced incomplete tail", n, err)
	}
	for _, raw := range []string{"x\n\tUser-Password = \"secret\"\n\n", "x\n\tPacket-Type = Access-Challenge\n\n", "x\n\tC8021X-Called = \"bad\\q\"\n\n"} {
		if _, _, err = Parse([]byte(raw)); err == nil {
			t.Fatal("accepted forbidden grammar")
		}
	}
}
func TestReaderRetainsFilesAndAtomicCursorOnOutage(t *testing.T) {
	dir, _ := filepath.EvalSymlinks(t.TempDir())
	_ = os.Chmod(dir, 0750)
	name := "auth-0123456789abcdef-2026100810.detail"
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(record+record[:30]), 0640); err != nil {
		t.Fatal(err)
	}
	_ = os.Chmod(path, 0640)
	store := &memoryStore{cursors: map[string]string{}, payloads: map[string]json.RawMessage{}, fail: true}
	r, err := newReader(Options{Directory: dir, Host: "fixture", ProducerUID: os.Getuid(), EventGID: os.Getgid(), Store: store}, false)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()
	if _, err = r.Poll(context.Background()); err == nil {
		t.Fatal("masked DB outage")
	}
	if len(store.cursors) != 0 {
		t.Fatal("advanced before transaction")
	}
	store.fail = false
	if n, err := r.Poll(context.Background()); err != nil || n != 1 {
		t.Fatal(n, err)
	}
	if n, err := r.Poll(context.Background()); err != nil || n != 0 {
		t.Fatal("replayed committed record", n, err)
	}
	if _, err = os.Stat(path); err != nil {
		t.Fatal("reader removed retained file")
	}
	f, _ := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	_, _ = f.WriteString(record[30:])
	_ = f.Close()
	if n, err := r.Poll(context.Background()); err != nil || n != 1 {
		t.Fatal(n, err)
	}
	if len(store.payloads) != 2 {
		t.Fatal(store.payloads)
	}
}
func TestReaderRejectsLinkedAndOversizedFiles(t *testing.T) {
	for _, kind := range []string{"symlink", "hardlink", "public", "oversized"} {
		t.Run(kind, func(t *testing.T) {
			dir, _ := filepath.EvalSymlinks(t.TempDir())
			_ = os.Chmod(dir, 0750)
			path := filepath.Join(dir, "auth-0123456789abcdef-2026100810.detail")
			target := filepath.Join(t.TempDir(), "target")
			_ = os.WriteFile(target, []byte(record), 0640)
			switch kind {
			case "symlink":
				_ = os.Symlink(target, path)
			case "hardlink":
				_ = os.Link(target, path)
			case "public":
				_ = os.WriteFile(path, []byte(record), 0644)
			case "oversized":
				_ = os.WriteFile(path, make([]byte, MaxRecord+1), 0640)
			}
			store := &memoryStore{cursors: map[string]string{}, payloads: map[string]json.RawMessage{}}
			r, err := newReader(Options{Directory: dir, Host: "fixture", ProducerUID: os.Getuid(), EventGID: os.Getgid(), Store: store}, false)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = r.Close() }()
			if _, err = r.Poll(context.Background()); err == nil {
				t.Fatal("accepted", kind)
			}
		})
	}
}

func TestReaderGenerationRotationRestartAndTruncation(t *testing.T) {
	dir, _ := filepath.EvalSymlinks(t.TempDir())
	_ = os.Chmod(dir, 0750)
	first := filepath.Join(dir, "auth-0123456789abcdef-2026100810.detail")
	second := filepath.Join(dir, "auth-fedcba9876543210-2026100810.detail")
	for _, path := range []string{first, second} {
		if e := os.WriteFile(path, []byte(record), 0640); e != nil {
			t.Fatal(e)
		}
		_ = os.Chmod(path, 0640)
	}
	store := &memoryStore{cursors: map[string]string{}, payloads: map[string]json.RawMessage{}}
	options := Options{Directory: dir, Host: "fixture", ProducerUID: os.Getuid(), EventGID: os.Getgid(), Store: store}
	reader, e := newReader(options, false)
	if e != nil {
		t.Fatal(e)
	}
	if n, e := reader.Poll(context.Background()); e != nil || n != 2 {
		t.Fatal("generation IDs collided", n, e)
	}
	_ = reader.Close()
	reader, e = newReader(options, false)
	if e != nil {
		t.Fatal(e)
	}
	defer func() { _ = reader.Close() }()
	if n, e := reader.Poll(context.Background()); e != nil || n != 0 {
		t.Fatal("restart reimported committed events", n, e)
	}
	if e = os.Truncate(first, 0); e != nil {
		t.Fatal(e)
	}
	if _, e = reader.Poll(context.Background()); e == nil {
		t.Fatal("accepted truncation below committed cursor")
	}
	if len(store.payloads) != 2 {
		t.Fatal("rewrote or duplicated immutable events")
	}
}

func TestRestorePreservesProducerGenerationAndDoesNotRecount(t *testing.T) {
	dir, _ := filepath.EvalSymlinks(t.TempDir())
	_ = os.Chmod(dir, 0750)
	path := filepath.Join(dir, "auth-0123456789abcdef-2026100810.detail")
	if err := os.WriteFile(path, []byte(record), 0640); err != nil {
		t.Fatal(err)
	}
	_ = os.Chmod(path, 0640)
	store := &memoryStore{cursors: map[string]string{}, payloads: map[string]json.RawMessage{}}
	reader, err := newReader(Options{Directory: dir, Host: "original-producer", ProducerUID: os.Getuid(), EventGID: os.Getgid(), Store: store}, false)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = reader.Close() }()
	if n, err := reader.Poll(context.Background()); err != nil || n != 1 {
		t.Fatal(n, err)
	}
	backup := path + ".restored"
	if err = os.WriteFile(backup, []byte(record+record), 0640); err != nil {
		t.Fatal(err)
	}
	_ = os.Chmod(backup, 0640)
	if err = os.Rename(backup, path); err != nil {
		t.Fatal(err)
	}
	if n, err := reader.Poll(context.Background()); err != nil || n != 1 {
		t.Fatal("restore recounted old event", n, err)
	}
	if len(store.payloads) != 2 {
		t.Fatal("duplicate business events after restored inode")
	}
}
