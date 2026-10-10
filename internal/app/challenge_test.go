package app

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/webhook/challenge"
)

func TestChallengeCommand(t *testing.T) {
	key := strings.Repeat("secret-key-", 4)
	keyFile := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(keyFile, []byte(key), 0600); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(t.TempDir(), "challenge")
	stdout, err := execute(t, context.Background(), nil, "scep-challenge", "--identity", "byod-enrollment-id", "--provisioner", "wifi-scep", "--signing-key-file", keyFile, "--out", output)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	token := strings.TrimSpace(string(data))
	if !challenge.Verify([]byte(key), token, "byod-enrollment-id", "wifi-scep", time.Now()) {
		t.Fatal("generated challenge does not authorize intended device")
	}
	if challenge.Verify([]byte(key), token, "staff-device", "wifi-scep", time.Now()) {
		t.Fatal("generated challenge authorizes another device")
	}
	info, err := os.Stat(output)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("challenge file must be private")
	}
	if strings.Contains(stdout, token) || strings.Contains(stdout, key) {
		t.Fatal("secret printed")
	}
}

func TestChallengeCommandDryRunAndInvalidTTL(t *testing.T) {
	keyFile := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(keyFile, []byte(strings.Repeat("k", 32)), 0600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"--dry-run"}, {"--ttl", "25h"}} {
		output := filepath.Join(t.TempDir(), "challenge")
		_, err := execute(t, context.Background(), nil, append([]string{"scep-challenge", "--identity", "device", "--provisioner", "wifi-scep", "--signing-key-file", keyFile, "--out", output}, args...)...)
		if (args[0] == "--dry-run") != (err == nil) {
			t.Fatalf("unexpected result: %v", err)
		}
		if _, err := os.Stat(output); !os.IsNotExist(err) {
			t.Fatal("must not write a token")
		}
	}
}
