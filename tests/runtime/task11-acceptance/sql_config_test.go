package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/CampusTech/cloud-8021x/internal/adoption"
	"github.com/CampusTech/cloud-8021x/internal/config"
	"github.com/CampusTech/cloud-8021x/internal/privileged/host"
)

// Only mode and bytes come from the real temporary fixture. Root ownership in
// SavedFile is synthetic unit data; this never asserts an installed receipt or
// substitutes for host.Snapshot's actual ancestry/type/owner/link checks.
func sqlConfigFixture(t *testing.T) (host.SavedFile, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	data := []byte("synthetic-shipping-config-codec-only\n")
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return host.SavedFile{File: host.File{Path: "/etc/cloud-8021x/config.yaml", UID: 0, Mode: uint32(info.Mode().Perm()), Data: raw}, Exists: true}, adoption.Digest(raw)
}

func TestSQLInstalledConfigAcceptsExactShippingMode(t *testing.T) {
	saved, pin := sqlConfigFixture(t)
	calls := 0
	if err := observeSQLConfig(pin, func(request host.File) (host.SavedFile, error) {
		calls++
		if request.Path != "/etc/cloud-8021x/config.yaml" || request.UID != 0 {
			t.Fatal("observer changed fixed installed path or required root owner")
		}
		return saved, nil
	}); err != nil {
		t.Fatal("exact pinned shipping0644 configuration refused", err)
	}
	if calls != 1 {
		t.Fatal("installed configuration was not captured once")
	}
	if !bytes.Equal(saved.Data, make([]byte, len(saved.Data))) {
		t.Fatal("installed configuration snapshot bytes were retained")
	}
}

func TestSQLInstalledConfigRejectsChangedAuthority(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*host.SavedFile, *string)
	}{
		{"private-mode", func(s *host.SavedFile, _ *string) { s.Mode = 0600 }},
		{"writable-mode", func(s *host.SavedFile, _ *string) { s.Mode = 0664 }},
		{"foreign-owner", func(s *host.SavedFile, _ *string) { s.UID = 12345 }},
		{"missing", func(s *host.SavedFile, _ *string) { s.Exists = false }},
		{"wrong-path", func(s *host.SavedFile, _ *string) { s.Path = "/etc/cloud-8021x/other.yaml" }},
		{"changed-bytes", func(s *host.SavedFile, _ *string) { s.Data[0] ^= 1 }},
		{"wrong-pin", func(_ *host.SavedFile, pin *string) { *pin = strings.Repeat("a", 64) }},
		{"oversized", func(s *host.SavedFile, pin *string) {
			s.Data = bytes.Repeat([]byte("x"), config.MaxConfigBytes+1)
			*pin = adoption.Digest(s.Data)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			saved, pin := sqlConfigFixture(t)
			tc.change(&saved, &pin)
			if err := observeSQLConfig(pin, func(request host.File) (host.SavedFile, error) {
				if request.Path != "/etc/cloud-8021x/config.yaml" || request.UID != 0 {
					t.Fatal("installed authority request changed")
				}
				return saved, nil
			}); err == nil {
				t.Fatal("changed installed configuration authority accepted")
			}
		})
	}
}

func TestSQLInstalledConfigPreservesSnapshotRefusal(t *testing.T) {
	saved, pin := sqlConfigFixture(t)
	if err := observeSQLConfig(pin, func(host.File) (host.SavedFile, error) {
		return saved, errors.New("synthetic protected Snapshot refusal")
	}); err == nil {
		t.Fatal("protected snapshot refusal converted to success")
	}
	if err := observeSQLConfig("invalid-pin", func(host.File) (host.SavedFile, error) {
		t.Fatal("invalid manifest pin reached snapshot")
		return host.SavedFile{}, nil
	}); err == nil {
		t.Fatal("invalid pin accepted")
	}
}
