package native

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSpoolObservationOnlyReadsMetadata(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "detail.work")
	if e := os.WriteFile(p, []byte("not parsed as accounting"), 0600); e != nil {
		t.Fatal(e)
	}
	health, e := ObserveSpool(dir, time.Now())
	if e != nil || health.Files != 1 || health.Bytes != 24 {
		t.Fatal(health, e)
	}
	if e = os.Symlink(p, filepath.Join(dir, "detail-bad")); e != nil {
		t.Fatal(e)
	}
	if _, e = ObserveSpool(dir, time.Now()); e == nil {
		t.Fatal("followed spool symlink")
	}
}
