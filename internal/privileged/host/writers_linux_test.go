package host

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInstalledLegacyWriterFenceRetainsAndRestoresExactFiles(t *testing.T) {
	if os.Getenv("C8021X_WRITER_FIXTURE") != "task9" {
		t.Skip("owned task9 root fixture required")
	}
	for _, path := range append(append([]string{}, legacyWriterCrons...), writerUnitPaths(legacyWriterUnits)...) {
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			t.Fatal(err)
		}
		data := []byte("# old sentinel\n")
		if strings.HasSuffix(path, "radius-usage-collector.service") {
			data = []byte("# Managed radius usage monitor; does not control FreeRADIUS.\n")
		}
		if err := os.WriteFile(path, data, 0644); err != nil {
			t.Fatal(err)
		}
	}
	run := func(context.Context, string, ...string) ([]byte, error) {
		return []byte("ActiveState=inactive\nSubState=dead\nMainPID=0\n"), nil
	}
	id, hash := strings.Repeat("a", 64), strings.Repeat("b", 64)
	digest, err := fenceLegacyWriters(context.Background(), id, "radius-primary", hash, run, func() error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if len(digest) != 64 {
		t.Fatal("missing durable evidence")
	}
	for _, path := range writerUnitPaths(legacyWriterUnits) {
		target, e := os.Readlink(path)
		if e != nil || target != "/dev/null" {
			t.Fatal("not persistently masked", path, e)
		}
	}
	for _, path := range legacyWriterCrons {
		data, e := os.ReadFile(path)
		if e != nil || !bytes.Contains(data, []byte("fenced")) {
			t.Fatal("cron remained active", e)
		}
	}
	again, err := fenceLegacyWriters(context.Background(), id, "radius-primary", hash, run, func() error { return nil })
	if err != nil || again != digest {
		t.Fatal("same evidence not idempotent", err)
	}
	if _, err = fenceLegacyWriters(context.Background(), id, "radius-primary", strings.Repeat("c", 64), run, func() error { return nil }); err == nil {
		t.Fatal("fence adopted different config")
	}
	if err = restoreLegacyWriterFiles(id, run); err != nil {
		t.Fatal(err)
	}
	for _, path := range legacyWriterCrons {
		data, e := os.ReadFile(path)
		if e != nil || string(data) != "# old sentinel\n" {
			t.Fatal("rollback altered old bytes", e)
		}
	}
}
