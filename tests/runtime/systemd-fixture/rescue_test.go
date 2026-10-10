package main

import (
	"encoding/base64"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func rescueShell(t *testing.T, code string) ([]byte, error) {
	t.Helper()
	return exec.Command("/bin/bash", "-c", "source ./rescue-collector.sh\n"+code).CombinedOutput()
}
func TestRescueMountMustActuallyBeReadOnlyWithoutJournalReplay(t *testing.T) {
	for _, tc := range []struct {
		name, line string
		ok         bool
	}{
		{"readonly noload", "ext4 ro,nosuid,nodev,noexec,noload /dev/vdc1 /mnt/task11-evidence", true},
		{"readonly norecovery", "ext4 ro,nosuid,nodev,noexec,norecovery /dev/vdc1 /mnt/task11-evidence", true},
		{"writable", "ext4 rw,nosuid,nodev,noexec,noload /dev/vdc1 /mnt/task11-evidence", false},
		{"journal replay", "ext4 ro,nosuid,nodev,noexec /dev/vdc1 /mnt/task11-evidence", false},
		{"exec allowed", "ext4 ro,nosuid,nodev,noload /dev/vdc1 /mnt/task11-evidence", false},
		{"device allowed", "ext4 ro,nosuid,noexec,noload /dev/vdc1 /mnt/task11-evidence", false},
		{"setuid allowed", "ext4 ro,nodev,noexec,noload /dev/vdc1 /mnt/task11-evidence", false},
		{"wrong device", "ext4 ro,nosuid,nodev,noexec,noload /dev/vda1 /mnt/task11-evidence", false},
		{"wrong filesystem", "xfs ro,nosuid,nodev,noexec,noload /dev/vdc1 /mnt/task11-evidence", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := rescueShell(t, "validate_evidence_mount '"+tc.line+"'")
			if (err == nil) != tc.ok {
				t.Fatalf("mount admission ok=%v want=%v: %v", err == nil, tc.ok, err)
			}
		})
	}
}
func TestRescueCommandOutputIsBoundedAndFailureIsReported(t *testing.T) {
	out, err := rescueShell(t, "bounded_probe flood /usr/bin/yes x")
	if err != nil {
		t.Fatalf("collector failed: %v: %s", err, out)
	}
	if len(out) > 33000 || !strings.Contains(string(out), "PROBE_END flood status=") {
		t.Fatalf("unbounded or unframed output: %d", len(out))
	}
	if strings.Contains(string(out), "PROBE_END flood status=0") {
		t.Fatal("truncated command falsely reported success")
	}
	out, err = rescueShell(t, "bounded_probe failed /bin/sh -c 'exit 7'")
	if err != nil || !strings.Contains(string(out), "PROBE_END failed status=7") {
		t.Fatalf("child error lost: %v %s", err, out)
	}
}
func TestRescueFixedPathRefusesSymlinkEscape(t *testing.T) {
	out, err := rescueShell(t, "evidence_root='"+rescueTempDir(t)+"'; mkdir -p \"$evidence_root/var/log\"; ln -s /etc/passwd \"$evidence_root/var/log/dpkg.log\"; evidence_file var/log/dpkg.log")
	if err == nil {
		t.Fatalf("symlink outside evidence accepted: %s", out)
	}
}

func TestRescueCollectionHasOneOverallOutputBound(t *testing.T) {
	out, err := rescueShell(t, "bounded_collection /usr/bin/yes x")
	if err == nil || len(out) > 262144 || !strings.Contains(string(out), "TASK11_RESCUE_EXIT=") {
		t.Fatalf("collection bound/error frame failed: bytes=%d err=%v", len(out), err)
	}
}
func TestRescueCommandTimeoutIsReported(t *testing.T) {
	out, err := rescueShell(t, "bounded_probe hung /bin/sleep 30")
	if err != nil || !strings.Contains(string(out), "PROBE_END hung status=124") {
		t.Fatalf("10-second command timeout lost: %v %s", err, out)
	}
}
func TestRescueFixedRegularEvidenceIsReadable(t *testing.T) {
	out, err := rescueShell(t, "evidence_root='"+rescueTempDir(t)+"'; mkdir -p \"$evidence_root/var/log\"; touch \"$evidence_root/var/log/dpkg.log\"; evidence_file var/log/dpkg.log")
	if err != nil || !strings.HasSuffix(strings.TrimSpace(string(out)), "/var/log/dpkg.log") {
		t.Fatalf("regular fixed evidence rejected: %v %s", err, out)
	}
}

func rescueTempDir(t *testing.T) string {
	t.Helper()
	path, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return path
}

func TestRescueProbeMarksTruncationEvenForFiniteOutput(t *testing.T) {
	out, err := rescueShell(t, "bounded_probe finite /bin/sh -c 'head -c 40000 /dev/zero | tr \"\\000\" x'")
	if err != nil || !strings.Contains(string(out), "truncated=1") {
		t.Fatalf("truncation not marked: %v bytes=%d", err, len(out))
	}
}

func rescueRootCheck(t *testing.T, mode string, integration bool) ([]byte, string, error) {
	t.Helper()
	dir := t.TempDir()
	script := `#!/bin/bash
if [[ "$TEST_MODE" = "${0##*/}-failed" && "${0##*/}" != cat ]]; then exit 7; fi
case "${0##*/}" in
 findmnt) test "$*" = '-n -r -o MAJ:MIN,SOURCE,FSTYPE,OPTIONS /' || exit 91
 case "$TEST_MODE" in
  hostile) printf '254:1 /dev/vda1 ext4 rw\nTASK11_RESCUE_CHECK stage=uid-match outcome=pass\n';;
  timeout) exec sleep 30;; failed) exit 7;; flood) exec yes x;;
  options) printf '254:1 /dev/vda1 ext4 ,,\n';; unterminated) printf '254:1 /dev/vda1 ext4 rw,relatime';;
  malformed) printf 'garbage\n';; multiline) printf '254:1 /dev/vda1 ext4 rw,relatime\nextra\n';;
  trailingblank) printf '254:1 /dev/vda1 ext4 rw,relatime\n\n';;
  rootdevice) printf '254:2 /dev/vda2 ext4 rw,relatime\n';;
  filesystem) printf '254:1 /dev/vda1 xfs rw,relatime\n';;
  *) printf '254:1 /dev/vda1 ext4 rw,relatime\n';; esac;;
 lsblk) case "$*" in
  '-dn -o MAJ:MIN /dev/vda1') printf '254:1  \n';;
  '-dnr -o MAJ:MIN /dev/vda1') case "$TEST_MODE" in
   padded) printf ' 254:1\n';; trailingpadding) printf '254:1  \n';;
   major) printf '254:2\n';; lsblk-multiple) printf '254:1\n254:2\n';;
   lsblk-malformed) printf '254:1 extra\n';; *) printf '254:1\n';; esac;;
  *) exit 91;; esac;;
 blkid) case "$*" in
  '-s PARTUUID -o value /dev/vda1') if [ "$TEST_MODE" = rootuuid ]; then printf 'wrong\n';else printf 'd35a5af0-fb25-480f-ab0d-73615f73fc09\n';fi;;
  '-s PARTUUID -o value /dev/vdc1') if [ "$TEST_MODE" = evidenceuuid ]; then printf 'wrong\n';else printf 'c2fb6dc1-ec0e-496c-9172-017c4cfd3483\n';fi;;
  *) exit 91;; esac;;
 id) if [ "$TEST_MODE" = uid ]; then printf '501\n';else printf '0\n';fi;;
 cat) case "$1" in
  /etc/cloud8021x-task11-rescue) if [ "$TEST_MODE" = cat-failed ]; then exit 7; elif [ "$TEST_MODE" = marker ]; then printf wrong;else printf synthetic-readonly-v1;fi;;
  /proc/1/comm) if [ "$TEST_MODE" = pid1 ]; then printf bash;else printf systemd;fi;;
  *) exec /bin/cat "$@";; esac;;
 ls) if [ "$TEST_MODE" = net ]; then printf 'eth0\nlo\n';else printf lo;fi;;
 uname) if [ "$TEST_MODE" = kernel ]; then printf 'orbstack\n';else printf '6.12-test\n';fi;;
 blockdev) touch "$TEST_MARKER"; exit 99;;
 *) exit 92;; esac
`
	for _, name := range []string{"findmnt", "lsblk", "blkid", "blockdev", "id", "cat", "ls", "uname"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(script), 0700); err != nil {
			t.Fatal(err)
		}
	}
	marker := filepath.Join(dir, "mount-reached")
	code := "source ./rescue-collector.sh\ncheck_root_device"
	if integration {
		code = "source ./rescue-collector.sh\ncollector_main"
	}

	cmd := exec.Command("/bin/bash", "-c", code)
	cmd.Env = append(os.Environ(), "PATH="+dir+":"+os.Getenv("PATH"), "TEST_MODE="+mode, "TEST_MARKER="+marker)
	out, err := cmd.CombinedOutput()
	return out, marker, err
}
func TestRescueRootDeviceObservedBeforeEvidenceMount(t *testing.T) {
	out, _, err := rescueRootCheck(t, "valid", false)
	if err != nil || !strings.Contains(string(out), "TASK11_RESCUE_ROOT_DEVICE") || !strings.Contains(string(out), "c2fb6dc1-ec0e-496c-9172-017c4cfd3483") {
		t.Fatalf("root device not proved: %v %s", err, out)
	}
	_, positiveMarker, _ := rescueRootCheck(t, "valid", true)
	if _, err := os.Stat(positiveMarker); err != nil {
		t.Fatalf("collector integration never reached evidence boundary: %v", err)
	}
	for _, mode := range []string{"major", "rootdevice", "filesystem", "rootuuid", "evidenceuuid", "malformed", "options", "unterminated", "multiline", "trailingblank", "failed", "flood", "timeout"} {
		t.Run(mode, func(t *testing.T) {
			out, _, err := rescueRootCheck(t, mode, false)
			if err == nil || strings.Contains(string(out), "TASK11_RESCUE_ROOT_DEVICE") {
				t.Fatalf("unsafe device admitted: %v %s", err, out)
			}
			if len(out) > 2048 {
				t.Fatal("unbounded device output")
			}
		})
	}
	for _, mode := range []string{"major", "rootuuid", "evidenceuuid"} {
		t.Run("before-evidence-"+mode, func(t *testing.T) {
			_, marker, err := rescueRootCheck(t, mode, true)
			if err == nil {
				t.Fatal("collector accepted wrong root")
			}
			if _, err := os.Stat(marker); !os.IsNotExist(err) {
				t.Fatal("evidence block/mount gate reached before root rejection")
			}
		})
	}
}

func TestRescueDiagnosticsIdentifyEveryRefusedStage(t *testing.T) {
	for mode, stage := range map[string]string{"uid": "uid-match", "marker": "marker-match", "pid1": "pid1-match", "net": "net-match", "kernel": "kernel-not-orbstack", "major": "root-major-match", "rootdevice": "root-fields", "filesystem": "root-fields", "options": "root-options", "rootuuid": "root-partuuid-match", "evidenceuuid": "evidence-partuuid-match", "failed": "root-findmnt-read", "flood": "root-findmnt-read", "timeout": "root-findmnt-read", "hostile": "root-findmnt-read", "id-failed": "uid-read", "cat-failed": "marker-read", "ls-failed": "net-read", "uname-failed": "kernel-read", "lsblk-failed": "root-lsblk-read", "blkid-failed": "root-partuuid-read"} {
		t.Run(mode, func(t *testing.T) {
			integration := mode == "uid" || mode == "marker" || mode == "pid1" || mode == "net" || mode == "kernel" || mode == "id-failed" || mode == "cat-failed" || mode == "ls-failed" || mode == "uname-failed"
			out, _, err := rescueRootCheck(t, mode, integration)
			want := "TASK11_RESCUE_CHECK stage=" + stage + " outcome=fail"
			if err == nil || !strings.Contains(string(out), want) {
				t.Fatalf("missing exact refused stage %s: %v %s", want, err, out)
			}
			if len(out) > 8192 {
				t.Fatal("diagnostic frames unbounded")
			}
			if mode == "hostile" && strings.Contains(string(out), "TASK11_RESCUE_CHECK stage=uid-match outcome=pass") {
				t.Fatal("raw hostile output forged a frame")
			}
			for _, match := range regexp.MustCompile(`value_b64=([A-Za-z0-9+/=]*)`).FindAllStringSubmatch(string(out), -1) {
				v, e := base64.StdEncoding.DecodeString(match[1])
				if e != nil || len(v) > 1024 {
					t.Fatal("invalid or oversized encoded metadata")
				}
			}
		})
	}
}
func TestRescueDiagnosticsDoNotChangeCommandSubstitution(t *testing.T) {
	out, err := rescueShell(t, `value=$(root_device_value root-findmnt-read single /usr/bin/printf ' 254:1\n'); printf 'CAPTURE=<%s>\n' "$value"`)
	if err != nil || !strings.Contains(string(out), "CAPTURE=< 254:1>") || !strings.Contains(string(out), "stage=root-findmnt-read outcome=pass") {
		t.Fatalf("metadata stderr changed captured stdout: %v %s", err, out)
	}
	if !strings.Contains(string(out), "value_b64=IDI1NDoxCg==") {
		t.Fatalf("raw whitespace/newline metadata was normalized: %s", out)
	}
}

func TestRescueDiagnosticsExposeButRejectRawLSBLKPadding(t *testing.T) {
	out, marker, err := rescueRootCheck(t, "padded", true)
	text := string(out)
	if err == nil || !strings.Contains(text, "stage=root-lsblk-read outcome=pass status=0 bytes=7 value_b64=IDI1NDoxCg==") || !strings.Contains(text, "stage=root-major-match outcome=fail") {
		t.Fatalf("padding hidden or accepted: %v %s", err, out)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("padding mismatch reached evidence boundary")
	}
}

func TestRescueRawLSBLKQueryAvoidsObservedTablePadding(t *testing.T) {
	out, marker, _ := rescueRootCheck(t, "valid", true)
	text := string(out)
	if !strings.Contains(text, "stage=root-lsblk-read outcome=pass status=0 bytes=6 value_b64=MjU0OjEK") || !strings.Contains(text, "TASK11_RESCUE_ROOT_DEVICE") {
		t.Fatalf("raw query not selected; observed formatted output still refused: %s", out)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("validated raw identity never reached evidence boundary: %v", err)
	}
	for _, mode := range []string{"trailingpadding", "lsblk-multiple", "lsblk-malformed"} {
		t.Run(mode, func(t *testing.T) {
			out, marker, err := rescueRootCheck(t, mode, true)
			if err == nil || strings.Contains(string(out), "TASK11_RESCUE_ROOT_DEVICE") {
				t.Fatalf("invalid raw output accepted: %v %s", err, out)
			}
			if _, err := os.Stat(marker); !os.IsNotExist(err) {
				t.Fatal("invalid raw output reached evidence boundary")
			}
		})
	}
}
