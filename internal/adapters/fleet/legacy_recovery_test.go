package fleet

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/migration"
)

func TestLegacyRecoveryReadsOriginalTerminalEvidence(t *testing.T) {
	for _, scenario := range []string{"terminal", "pending", "wrong-host", "predates", "foreign-result", "absent"} {
		t.Run(scenario, func(t *testing.T) {
			calls := 0
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				if r.Method != "GET" || r.Header.Get("Authorization") != "Bearer observer" {
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
			client, e := NewClient(server.URL, "observer", server.Client(), time.Second)
			if e != nil {
				t.Fatal(e)
			}
			binding := []json.RawMessage{json.RawMessage(`42`), json.RawMessage(`1791450000.123456789`), json.RawMessage(`null`)}
			host := migration.LegacyCertificateHost{Binding: binding, Platform: "darwin"}
			command := migration.LegacyCommand{UUID: "original-command", CreatedAt: json.Number("1791460800"), Hosts: map[string][]json.RawMessage{"host-42": binding}}
			proof, e := client.RecoverLegacyCommand(context.Background(), server.URL, "host-42", host, command, "")
			good := scenario == "terminal" || scenario == "absent"
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
