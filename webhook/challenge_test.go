package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/CampusTech/cloud-8021x/webhook/internal/challenge"
)

func TestChallengeCommand(t *testing.T) {
	key := strings.Repeat("secret-key-", 4)
	t.Setenv("SCEP_CHALLENGE_SIGNING_KEY", key)
	output := filepath.Join(t.TempDir(), "challenge")
	cmd := newRootCmd()
	cmd.SetArgs([]string{"scep-challenge", "--identity", "byod-enrollment-id", "--provisioner", "wifi-scep", "--out", output})
	var stdout bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stdout)
	if err := cmd.Execute(); err != nil {
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
	if strings.Contains(stdout.String(), token) || strings.Contains(stdout.String(), key) {
		t.Fatal("secret printed")
	}
}

func TestChallengeCommandDryRunAndInvalidTTL(t *testing.T) {
	t.Setenv("SCEP_CHALLENGE_SIGNING_KEY", strings.Repeat("k", 32))
	for _, args := range [][]string{{"--dry-run"}, {"--ttl", "25h"}} {
		output := filepath.Join(t.TempDir(), "challenge")
		cmd := newRootCmd()
		cmd.SetArgs(append([]string{"scep-challenge", "--identity", "device", "--provisioner", "wifi-scep", "--out", output}, args...))
		err := cmd.Execute()
		if (args[0] == "--dry-run") != (err == nil) {
			t.Fatalf("unexpected result: %v", err)
		}
		if _, err := os.Stat(output); !os.IsNotExist(err) {
			t.Fatal("must not write a token")
		}
	}
}
