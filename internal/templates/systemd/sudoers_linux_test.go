package systemd

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

type nativeAccountState struct {
	UID, GID, Shell, Expiry string
	PasswordLocked          bool
}

func nativeAccount(t *testing.T) nativeAccountState {
	t.Helper()
	u, err := user.Lookup("freerad")
	if err != nil {
		t.Fatal(err)
	}
	passwd, err := os.ReadFile("/etc/passwd")
	if err != nil {
		t.Fatal(err)
	}
	var shell string
	for _, line := range strings.Split(string(passwd), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) == 7 && fields[0] == "freerad" {
			shell = fields[6]
		}
	}
	shadow, err := os.ReadFile("/etc/shadow")
	if err != nil {
		t.Fatal("read disposable account state:", err)
	}
	for _, line := range strings.Split(string(shadow), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) == 9 && fields[0] == "freerad" {
			return nativeAccountState{UID: u.Uid, GID: u.Gid, Shell: shell, Expiry: fields[7], PasswordLocked: strings.HasPrefix(fields[1], "!") || strings.HasPrefix(fields[1], "*")}
		}
	}
	t.Fatal("native account shadow entry absent")
	return nativeAccountState{}
}

// This fixture installs the actual pinned Debian13 native package; its u! entry
// creates an expired account. A useradd-only fixture would miss this regression.
func TestFreshDebianNativeAccountAllowsOnlyFixedLeaf(t *testing.T) {
	if os.Getenv("C8021X_SUDO_FIXTURE") != "task11-protocol" {
		t.Skip("owned actual Debian13 package fixture required")
	}
	if os.Geteuid() != 0 {
		t.Fatal("owned fixture requires root")
	}
	before := nativeAccount(t)
	if !before.PasswordLocked || before.Shell != "/usr/sbin/nologin" || before.Expiry != "1" {
		t.Fatal("fixture must retain actual package-created locked, nologin, expired account", before)
	}
	files, err := Render()
	if err != nil {
		t.Fatal(err)
	}
	policy := "/etc/sudoers.d/cloud-8021x"
	if err = os.WriteFile(policy, files[policy], 0440); err != nil {
		t.Fatal(err)
	}
	// Remove only the obsolete test-owned wildcard rule, so it cannot mask a
	// rejection from the shipping anchored command policy.
	if err = os.Remove("/etc/sudoers.d/task6-leaf"); err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	if output, err := exec.Command("/usr/sbin/visudo", "-cf", policy).CombinedOutput(); err != nil {
		t.Fatalf("actual rendered sudoers: %v %s", err, output)
	}
	leaf := "/run/radius-verified-leaves/fixture.pem"
	certificatePEM, err := os.ReadFile("/task6/certs/personal.pem")
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(leaf, certificatePEM, 0600); err != nil {
		t.Fatal(err)
	}
	uid, err := strconv.Atoi(before.UID)
	if err != nil {
		t.Fatal(err)
	}
	gid, err := strconv.Atoi(before.GID)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Chown(leaf, uid, gid); err != nil {
		t.Fatal(err)
	}
	nonce := strings.Repeat("b", 64)
	arguments := []string{"--config", "/etc/cloud-8021x/config.yaml", "radius", "verify-leaf", leaf, nonce}
	sudo := func(command string, args ...string) ([]byte, error) {
		t.Helper()
		invocation := []string{"--user", "freerad", "--", "/usr/bin/sudo", "-n", command}
		return exec.Command("/usr/sbin/runuser", append(invocation, args...)...).CombinedOutput()
	}
	if output, err := sudo("/usr/local/bin/cloud-8021x", arguments...); err != nil {
		t.Fatalf("exact permitted helper on expired package account: %v %s", err, output)
	}
	block, _ := pem.Decode(certificatePEM)
	if block == nil {
		t.Fatal("fixture certificate PEM absent")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint := sha256.Sum256(certificate.Raw)
	binding := filepath.Join("/run/radius-certificate-bindings", nonce)
	data, err := os.ReadFile(binding)
	if err != nil || !bytes.Equal(data, []byte(hex.EncodeToString(fingerprint[:]))) {
		t.Fatal("real helper failed to publish the exact verified fingerprint", err)
	}
	var stat unix.Stat_t
	if err := unix.Stat(binding, &stat); err != nil || stat.Mode&0777 != 0600 || stat.Uid == uint32(uid) {
		t.Fatal("real fingerprint binding is not isolated from native UID", err)
	}
	denied := []struct {
		name, command string
		args          []string
	}{
		{"id", "/usr/bin/id", nil},
		{"renewal", "/usr/local/bin/cloud-8021x", []string{"--config", "/etc/cloud-8021x/config.yaml", "certificates", "renew"}},
		{"wrong-config", "/usr/local/bin/cloud-8021x", []string{"--config", "/etc/cloud-8021x/other.yaml", "radius", "verify-leaf", leaf, nonce}},
		{"wrong-digest", "/usr/local/bin/cloud-8021x", []string{"--config", "/etc/cloud-8021x/config.yaml", "radius", "verify-leaf", leaf, strings.Repeat("g", 64)}},
		{"short-digest", "/usr/local/bin/cloud-8021x", []string{"--config", "/etc/cloud-8021x/config.yaml", "radius", "verify-leaf", leaf, nonce[:63]}},
		{"traversal", "/usr/local/bin/cloud-8021x", []string{"--config", "/etc/cloud-8021x/config.yaml", "radius", "verify-leaf", "/run/radius-verified-leaves/../fixture.pem", nonce}},
		{"extra-argument", "/usr/local/bin/cloud-8021x", append(append([]string{}, arguments...), "extra")},
		{"missing-argument", "/usr/local/bin/cloud-8021x", arguments[:len(arguments)-1]},
	}
	for _, check := range denied {
		t.Run(check.name, func(t *testing.T) {
			output, err := sudo(check.command, check.args...)
			if err == nil || !bytes.Contains(output, []byte("sudo:")) {
				t.Fatalf("sudo must deny unrelated or malformed command before application execution: %v %s", err, output)
			}
		})
	}
	// An inert, test-only otherwise-authorized command still receives the
	// global PAM account validation. It cannot inherit the leaf exception.
	outside := "/etc/sudoers.d/task11-protocol-pam-control"
	if err := os.WriteFile(outside, []byte("freerad ALL=(root) NOPASSWD: /usr/bin/true\n"), 0440); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(outside) })
	if output, err := sudo("/usr/bin/true"); err == nil || !bytes.Contains(output, []byte("account validation failure")) {
		t.Fatalf("command-scoped policy disabled account checks globally: %v %s", err, output)
	}
	if after := nativeAccount(t); !reflect.DeepEqual(before, after) {
		t.Fatal("helper policy changed locked account state", before, after)
	}
	t.Log("actual expired native account: fixed helper/fingerprint permitted; unrelated/invalid commands denied; global PAM and account state preserved")
}
