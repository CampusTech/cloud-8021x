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
	for _, scenario := range []string{"terminal", "pending", "wrong-host", "predates", "foreign-result", "absent", "empty"} {
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
					_ = json.NewEncoder(w).Encode(map[string]any{"host": map[string]any{"id": 42, "uuid": uuid}})
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
			binding := []json.RawMessage{json.RawMessage(`42`), json.RawMessage(`1791450000.123456789`), json.RawMessage(`null`)}
			host := migration.LegacyCertificateHost{Binding: binding, Platform: "darwin"}
			command := migration.LegacyCommand{UUID: "original-command", CreatedAt: json.Number("1791460800"), Hosts: map[string][]json.RawMessage{"host-42": binding}}
			proof, e := client.RecoverLegacyCommand(context.Background(), server.URL, "host-42", host, command, "")
			good := scenario == "terminal"
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
	for _, scenario := range []string{"terminal", "known-absent", "unknown-absent", "hint-terminal", "pending", "wrong-script", "wrong-nonce", "wrong-host", "predates", "empty"} {
		t.Run(scenario, func(t *testing.T) {
			script := "Write-Output 'fixture'\n"
			hash := sha256.Sum256([]byte(script))
			zero := 0
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != "GET" || r.Header.Get("Authorization") != "Bearer scoped-maintainer" {
					t.Error("unexpected method/credential")
				}
				if r.URL.Path == "/api/v1/fleet/hosts/42" {
					_, _ = w.Write([]byte(`{"host":{"id":42,"uuid":"host-42"}}`))
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
			binding := []json.RawMessage{json.RawMessage(`42`), json.RawMessage(`1791450000.123456789`), json.RawMessage(`null`), digest}
			host := migration.LegacyCertificateHost{Binding: binding, Platform: "windows"}
			command := migration.LegacyCommand{UUID: "original-command", Transport: "windows_script", ExecutionID: "execution-42", CreatedAt: json.Number("1791460800"), Hosts: map[string][]json.RawMessage{"host-42": binding}}
			hint := ""
			if scenario == "unknown-absent" || scenario == "hint-terminal" {
				command.ExecutionID = ""
				hint = "execution-42"
			}
			proof, e := client.RecoverLegacyCommand(context.Background(), server.URL, "host-42", host, command, hint)
			good := scenario == "terminal" || scenario == "hint-terminal"
			if (e == nil) != good {
				t.Fatalf("scenario %s proof=%+v error=%v", scenario, proof, e)
			}
		})
	}
}
