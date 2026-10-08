package auth

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

type retentionStore struct{ memoryStore }

func (s *retentionStore) AuthCursors(_ context.Context, sources []string) (map[string]string, error) {
	out := map[string]string{}
	for _, source := range sources {
		out[source] = s.cursors[source]
	}
	return out, nil
}
func TestClosedGenerationRetentionRequiresExactCursorAndNeverUsesAge(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root retention fixture required")
	}
	dir, _ := filepath.EvalSymlinks(t.TempDir())
	_ = os.Chmod(dir, 0750)
	closed, current, rollback := strings.Repeat("a", 32), strings.Repeat("b", 32), strings.Repeat("c", 32)
	store := &retentionStore{memoryStore{cursors: map[string]string{}, payloads: map[string]json.RawMessage{}}}
	names := []string{"auth-" + closed + "-1999010100.detail", "auth-" + closed + "-2026100810.detail", "auth-" + current + "-1999010100.detail", "auth-" + rollback + "-1999010100.detail"}
	for i, name := range names {
		if e := os.WriteFile(filepath.Join(dir, name), []byte(record), 0640); e != nil {
			t.Fatal(e)
		}
		_ = os.Chmod(filepath.Join(dir, name), 0640)
		store.cursors["fixture/"+name] = strconv.Itoa(len(record))
		if i == 1 {
			store.cursors["fixture/"+name] = "0"
		}
	}
	reader, e := newReader(Options{Directory: dir, Host: "fixture", ProducerUID: os.Getuid(), EventGID: os.Getgid(), Store: store}, false)
	if e != nil {
		t.Fatal(e)
	}
	defer func() { _ = reader.Close() }()
	result, e := reader.PruneClosed(context.Background(), map[string]bool{closed: true}, store)
	if e != nil || result.Removed != 1 || result.Retained != 1 {
		t.Fatalf("result=%+v error=%v", result, e)
	}
	for i, name := range names {
		_, e := os.Stat(filepath.Join(dir, name))
		if (e == nil) != (i != 0) {
			t.Fatalf("wrong retention %s %v", name, e)
		}
	}
}
