package fleet

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/migration"
)

func TestLegacyRecoveryReadsOriginalTerminalEvidence(t *testing.T) {
	for _, scenario := range []string{"terminal", "same-second", "changed-enrollment", "missing-enrollment", "changed-fleet-enrollment", "missing-fleet-enrollment", "wrong-platform", "pending", "wrong-host", "predates", "foreign-result", "absent", "empty"} {
		t.Run(scenario, func(t *testing.T) {
			calls := 0
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				if r.Method != "GET" || r.Header.Get("Authorization") != "Bearer scoped-maintainer" {
					t.Errorf("unexpected mutation or credential: %s", r.Method)
				}
				switch r.URL.Path {
				case "/api/v1/fleet/hosts/42":
					uuid := "host-42"
					if scenario == "wrong-host" {
						uuid = "replacement"
					}
					_ = json.NewEncoder(w).Encode(map[string]any{"host": legacyRecoveryHost(scenario, uuid, "darwin")})
				case "/api/v1/fleet/commands/results":
					if r.URL.Query().Get("command_uuid") != "original-command" {
						t.Error("lost original command")
					}
					if scenario == "absent" {
						w.WriteHeader(404)
						return
					}
					if scenario == "empty" {
						_, _ = w.Write([]byte(`{"results":[]}`))
						return
					}
					row := appleResult{HostUUID: "host-42", CommandUUID: "original-command", RequestType: "CertificateList", Status: "Acknowledged", UpdatedAt: "2026-10-08T12:00:01Z", Result: "original-output"}
					if scenario == "pending" {
						row.Status = "NotNow"
					}
					if scenario == "same-second" {
						row.UpdatedAt = "2026-10-08T12:00:00Z"
					}
					if scenario == "predates" {
						row.UpdatedAt = "2026-10-08T11:59:59Z"
					}
					if scenario == "foreign-result" {
						row.HostUUID = "foreign"
					}
					_ = json.NewEncoder(w).Encode(map[string]any{"results": []appleResult{row}})
				default:
					t.Errorf("unexpected path %s", r.URL.Path)
					w.WriteHeader(404)
				}
			}))
			defer server.Close()
			client, e := NewClient(server.URL, "scoped-maintainer", server.Client(), time.Second)
			if e != nil {
				t.Fatal(e)
			}
			binding := []json.RawMessage{json.RawMessage(`42`), json.RawMessage(`1791450000.123456`), json.RawMessage(`"2026-10-08T09:00:00.123456789Z"`)}
			host := migration.LegacyCertificateHost{Binding: binding, Platform: "darwin"}
			command := migration.LegacyCommand{UUID: "original-command", CreatedAt: json.Number("1791460800.75"), Hosts: map[string][]json.RawMessage{"host-42": binding}}
			original, _ := json.Marshal(command)
			proof, e := client.RecoverLegacyCommand(context.Background(), server.URL, "host-42", host, command, "")
			after, _ := json.Marshal(command)
			if string(after) != string(original) {
				t.Fatal("original reservation mutated")
			}
			if scenario == "same-second" && !strings.Contains(string(proof.Response), "2026-10-08T12:00:00Z") {
				t.Error("original result time not retained")
			}
			good := scenario == "terminal" || scenario == "same-second"
			if (e == nil) != good {
				t.Fatalf("proof=%+v err=%v", proof, e)
			}
			if good && (proof.HostID != 42 || proof.CommandUUID != "original-command" || len(proof.Response) == 0) {
				t.Fatalf("lost original evidence: %+v", proof)
			}
			if scenario == "wrong-host" && calls != 1 {
				t.Fatal("queried results after host replacement")
			}
		})
	}
}

func TestLegacyWindowsRecoveryUsesExactOriginalScriptAndExecution(t *testing.T) {
	for _, scenario := range []string{"terminal", "same-second", "changed-enrollment", "missing-enrollment", "changed-fleet-enrollment", "missing-fleet-enrollment", "wrong-platform", "known-absent", "unknown-absent", "hint-terminal", "pending", "wrong-script", "wrong-nonce", "wrong-host", "predates", "empty"} {
		t.Run(scenario, func(t *testing.T) {
			script := "Write-Output 'fixture'\n"
			hash := sha256.Sum256([]byte(script))
			zero := 0
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != "GET" || r.Header.Get("Authorization") != "Bearer scoped-maintainer" {
					t.Error("unexpected method/credential")
				}
				if r.URL.Path == "/api/v1/fleet/hosts/42" {
					_ = json.NewEncoder(w).Encode(map[string]any{"host": legacyRecoveryHost(scenario, "host-42", "windows")})
					return
				}
				if r.URL.Path != "/api/v1/fleet/scripts/results/execution-42" {
					t.Error("wrong execution path", r.URL.Path)
					w.WriteHeader(404)
					return
				}
				if strings.HasSuffix(scenario, "absent") {
					w.WriteHeader(404)
					return
				}
				if scenario == "empty" {
					_, _ = w.Write([]byte(`{}`))
					return
				}
				row := windowsResult{HostID: 42, ExecutionID: "execution-42", Script: script + "\n# Collection nonce: original-command\n", ExitCode: &zero, CreatedAt: "2026-10-08T12:00:01Z", Output: "original-output"}
				switch scenario {
				case "pending":
					row.ExitCode = nil
				case "wrong-script":
					row.Script = "different\n# Collection nonce: original-command\n"
				case "wrong-nonce":
					row.Script = script + "\n# Collection nonce: other\n"
				case "wrong-host":
					row.HostID = 43
				case "same-second":
					row.CreatedAt = "2026-10-08T12:00:00Z"
				case "predates":
					row.CreatedAt = "2026-10-08T11:59:59Z"
				}
				_ = json.NewEncoder(w).Encode(row)
			}))
			defer server.Close()
			client, e := NewClient(server.URL, "scoped-maintainer", server.Client(), time.Second)
			if e != nil {
				t.Fatal(e)
			}
			digest, _ := json.Marshal(hex.EncodeToString(hash[:]))
			binding := []json.RawMessage{json.RawMessage(`42`), json.RawMessage(`1791450000.123456`), json.RawMessage(`"2026-10-08T09:00:00.123456789Z"`), digest}
			host := migration.LegacyCertificateHost{Binding: binding, Platform: "windows"}
			command := migration.LegacyCommand{UUID: "original-command", Transport: "windows_script", ExecutionID: "execution-42", CreatedAt: json.Number("1791460800.75"), Hosts: map[string][]json.RawMessage{"host-42": binding}}
			hint := ""
			if scenario == "unknown-absent" || scenario == "hint-terminal" {
				command.ExecutionID = ""
				hint = "execution-42"
			}
			original, _ := json.Marshal(command)
			proof, e := client.RecoverLegacyCommand(context.Background(), server.URL, "host-42", host, command, hint)
			after, _ := json.Marshal(command)
			if string(after) != string(original) {
				t.Fatal("original reservation mutated")
			}
			if scenario == "same-second" && !strings.Contains(string(proof.Response), "2026-10-08T12:00:00Z") {
				t.Error("original result time not retained")
			}
			good := scenario == "terminal" || scenario == "same-second" || scenario == "hint-terminal"
			if (e == nil) != good {
				t.Fatalf("scenario %s proof=%+v error=%v", scenario, proof, e)
			}
		})
	}
}

func legacyRecoveryHost(scenario, uuid, platform string) map[string]any {
	h := map[string]any{"id": 42, "uuid": uuid, "platform": platform, "last_enrolled_at": "2026-10-08T09:00:00.123456789Z", "last_mdm_enrolled_at": "2026-10-08T09:00:00.123456789Z"}
	field := "last_mdm_enrolled_at"
	if platform == "windows" {
		field = "last_enrolled_at"
	}
	switch scenario {
	case "changed-enrollment":
		h[field] = "2026-10-08T09:00:01Z"
	case "missing-enrollment":
		delete(h, field)
	case "changed-fleet-enrollment":
		h["last_enrolled_at"] = "2026-10-08T09:00:01Z"
	case "missing-fleet-enrollment":
		delete(h, "last_enrolled_at")
	case "wrong-platform":
		h["platform"] = "linux"
	}
	return h
}
