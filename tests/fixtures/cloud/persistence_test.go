package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/adapters/otlp"
	"github.com/CampusTech/cloud-8021x/internal/telemetry"
	logscollect "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	common "go.opentelemetry.io/proto/otlp/common/v1"

	"golang.org/x/sys/unix"
)

func persistentFixture(t *testing.T, root string) *fixture {
	t.Helper()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	f := fleetFixture(t)
	f.phase = "active"
	f.stateRoot = root
	f.config.Secrets["projects/111222333444/secrets/radius-smallstep-server-cert"] = map[string]string{"1": base64.StdEncoding.EncodeToString([]byte("original"))}
	file, err := privateFile(filepath.Join(root, "journal.jsonl"), unix.O_CREAT|unix.O_APPEND|unix.O_WRONLY)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = file.Close() })
	f.journal = file
	return f
}
func TestRemoteRestartPreservesImmutableVersionsAndRejectsJournalTamper(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	f := persistentFixture(t, root)
	body := `{"payload":{"data":"bmV3","dataCrc32c":"` + crcString([]byte("new")) + `"}}`
	secretRequest(t, f, "POST", "radius-smallstep-server-cert:addVersion", body, 200)
	reloaded := persistentFixture(t, root)
	secretRequest(t, reloaded, "GET", "radius-smallstep-server-cert/versions/2:access", "", 200)
	if len(reloaded.remote.Secrets["projects/111222333444/secrets/radius-smallstep-server-cert"]) != 2 {
		t.Fatal("remote state lost on restart")
	}
	if err := os.WriteFile(filepath.Join(root, "journal.jsonl"), []byte("{}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if release, err := reloaded.openRemote(); err == nil {
		release()
		t.Fatal("forged/hash-only journal accepted")
	}
}
func TestPrivateStateSymlinkAndModeRefusal(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(root, "foreign")
	if err := os.WriteFile(target, []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(root, "remote-state.json")); err != nil {
		t.Fatal(err)
	}
	f := persistentFixture(t, root)
	if release, err := f.openRemote(); err == nil {
		release()
		t.Fatal("state symlink followed")
	}
	if err := os.Remove(filepath.Join(root, "remote-state.json")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "remote-state.json"), []byte("{}"), 0644); err != nil {
		t.Fatal(err)
	}
	if release, err := f.openRemote(); err == nil {
		release()
		t.Fatal("public state accepted")
	}
}

func TestPrivateEvidenceRejectsHardlinkAndAncestorSymlink(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(root, "payload")
	if err = os.WriteFile(file, []byte("private"), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "duplicate")
	if err = os.Link(file, link); err != nil {
		t.Fatal(err)
	}
	if _, err = privateRead(file); err == nil {
		t.Error("hardlinked evidence accepted")
	}
	if err = os.Remove(link); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(root, "alias")
	if err = os.Symlink(root, alias); err != nil {
		t.Fatal(err)
	}
	if _, err = privateRead(filepath.Join(alias, "payload")); err == nil {
		t.Error("ancestor symlink followed")
	}
}

func TestPersistentSeedPinUsesExactReviewedFileBytes(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	source := fleetFixture(t)
	raw, err := json.MarshalIndent(source.config, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	raw = append(raw, '\n')
	if err = os.WriteFile(filepath.Join(root, "seed.json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	f, err := loadFixture(root, "active", &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	f.initializeRemote()
	if f.remote.SeedSHA256 != digestBytes(raw) {
		t.Fatal("persistent seed pin differs from exact reviewed file bytes")
	}
}

func TestPrivateReopenedVerifierPreservesNumericPrimaries(t *testing.T) {
	for _, tc := range []struct {
		name, expected, change string
		want                   bool
	}{
		{"correct 2^53+1", "9007199254740993", "", true},
		{"correct MaxInt64", "9223372036854775807", "", true},
		{"adjacent wrong primary rounds to even", "9007199254740992", "adjacent", false},
		{"MaxUint64 deliberate double plus exact", "18446744073709551615", "", true},
		{"wrong primary kind", "5", "kind", false},
		{"private extra attribute", "18446744073709551615", "private", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, expected := completePrimitiveEvidence(t, func(request *logscollect.ExportLogsServiceRequest) {
				log := request.ResourceLogs[0].ScopeLogs[0].LogRecords[0]
				var fields map[string]any
				decoder := json.NewDecoder(strings.NewReader(log.Body.GetStringValue()))
				decoder.UseNumber()
				if err := decoder.Decode(&fields); err != nil {
					t.Fatal(err)
				}
				fields["input_bytes"] = json.Number(tc.expected)
				// Generate the correct independent counter representation using the real
				// encoder, then change only the observed primary for the negative cases.
				*request = *otlp.Request([]telemetry.BusinessRecord{{ID: "actual-id", Category: "usage", Host: "green-primary", Received: time.Unix(1800000000, 0), Fields: fields}})
				log = request.ResourceLogs[0].ScopeLogs[0].LogRecords[0]
				for _, kv := range log.Attributes {
					if kv.Key == "input_bytes" {
						switch tc.change {
						case "adjacent":
							kv.Value.Value = &common.AnyValue_IntValue{IntValue: 9007199254740993}
						case "kind":
							kv.Value.Value = &common.AnyValue_DoubleValue{DoubleValue: 5}
						}
					}
				}
				if tc.change == "private" {
					log.Attributes = append(log.Attributes, &common.KeyValue{Key: "tls_private_key", Value: &common.AnyValue{Value: &common.AnyValue_StringValue{StringValue: "must refuse"}}})
				}
			})
			expected.Records[0].Fields["input_bytes"] = json.Number(tc.expected)
			if _, err := f.verifyEvidence(expected, expected.ApplicationSHA256); (err == nil) != tc.want {
				t.Fatalf("in-memory control: %v", err)
			}
			root, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			if err = os.Chmod(root, 0700); err != nil {
				t.Fatal(err)
			}
			seed, err := json.Marshal(f.config)
			if err != nil {
				t.Fatal(err)
			}
			if err = os.WriteFile(filepath.Join(root, "seed.json"), seed, 0600); err != nil {
				t.Fatal(err)
			}
			if err = os.WriteFile(filepath.Join(root, "journal.jsonl"), f.journal.(*bytes.Buffer).Bytes(), 0600); err != nil {
				t.Fatal(err)
			}
			projected, err := json.Marshal(expected)
			if err != nil {
				t.Fatal(err)
			}
			if err = os.WriteFile(filepath.Join(root, "expected.json"), projected, 0600); err != nil {
				t.Fatal(err)
			}
			f.stateRoot = root
			if err = f.commitRemote(); err != nil {
				t.Fatal(err)
			}
			// Match the real fixed-path verify command's private reads, seed loading,
			// locked durable reload/audit and final projection verification. No reused
			// in-memory fixture or decoded attribute map crosses this boundary.
			journal, err := privateFile(filepath.Join(root, "journal.jsonl"), unix.O_APPEND|unix.O_WRONLY)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = journal.Close() }()
			reopened, err := loadFixture(root, "active", journal)
			if err != nil {
				t.Fatal(err)
			}
			release, err := reopened.openRemote()
			if err != nil {
				t.Fatal(err)
			}
			defer release()
			projectedAgain, err := privateRead(filepath.Join(root, "expected.json"))
			if err != nil {
				t.Fatal(err)
			}
			if digestBytes(projectedAgain) != digestBytes(projected) {
				t.Fatal("projection pin changed")
			}
			pinned, err := parsedProjection(projectedAgain)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = reopened.verifyEvidence(pinned, pinned.ApplicationSHA256); (err == nil) != tc.want {
				t.Fatalf("persisted/reopened verifier success=%v want=%v: %v", err == nil, tc.want, err)
			}
		})
	}
}
