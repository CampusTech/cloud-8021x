package fleet

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/migration"
)

func TestNewCollectionRecoveryExactTerminalOnly(t *testing.T) {
	enrollment := "2026-10-01T00:00:00Z"
	for _, status := range []string{"Acknowledged", "Error", "404", "empty", "pending", "changed-enrollment"} {
		t.Run(status, func(t *testing.T) {
			calls := 0
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				if r.Method != "GET" || r.Header.Get("Authorization") != "Bearer maintainer" {
					t.Error("unsafe recovery request")
				}
				if r.URL.Path == "/api/v1/fleet/hosts/42" {
					at := enrollment
					if status == "changed-enrollment" {
						at = "2026-10-02T00:00:00Z"
					}
					_, _ = fmt.Fprintf(w, `{"host":{"id":42,"uuid":"host-42","platform":"darwin","last_mdm_enrolled_at":%q,"last_enrolled_at":%q}}`, at, enrollment)
					return
				}
				if r.URL.Query().Get("command_uuid") != "original-command" {
					t.Error("wrong original command")
				}
				if status == "404" {
					w.WriteHeader(404)
					return
				}
				if status == "empty" {
					_, _ = w.Write([]byte(`{"results":[]}`))
					return
				}
				result := status
				if status == "pending" {
					result = "Pending"
				}
				_, _ = fmt.Fprintf(w, `{"results":[{"host_uuid":"host-42","command_uuid":"original-command","request_type":"CertificateList","status":%q,"updated_at":"2026-10-08T10:00:00Z","result":""}]}`, result)
			}))
			defer srv.Close()
			client, _ := NewClient(srv.URL, "maintainer", srv.Client(), time.Second)
			trust := strings.Repeat("a", 64)
			binding := fmt.Sprintf("%s\x00%d\x00%s\x00%s\x00%s\x00%s\x00%s", srv.URL, 42, "host-42", enrollment, enrollment, trust, "apple")
			sum := sha256.Sum256([]byte(binding))
			r := reservation{ManagedOnly: true, Key: hex.EncodeToString(sum[:]), LegacyScope: migration.LegacyCollectionScope(srv.URL, 42, "host-42"), UUID: "original-command", HostID: 42, HostUUID: "host-42", EnrolledAt: 1790812800, FleetEnrolledAt: enrollment, CreatedAt: 1791450000, Transport: "apple", Trust: trust}
			raw, _ := json.Marshal(r)
			proof, e := client.RecoverCollectionWork(context.Background(), raw, json.RawMessage(`{"pending":true}`), nil)
			terminal := status == "Acknowledged" || status == "Error"
			if (e == nil) != terminal {
				t.Fatalf("status=%s proof=%+v err=%v", status, proof, e)
			}
			if terminal && (proof.Outcome != "terminal" || proof.CommandUUID != r.UUID || len(proof.Response) == 0) {
				t.Fatal(proof)
			}
			if calls > 3 {
				t.Fatal("unbounded collection recovery")
			}
		})
	}
}

func TestNewWindowsRecoveryRetainsExactBindingAndTimestampBound(t *testing.T) {
	for _, scenario := range []string{"terminal", "hint-terminal", "changed-enrollment", "missing-enrollment", "same-second-before-request"} {
		t.Run(scenario, func(t *testing.T) {
			enrollment := "2026-10-01T00:00:00.123456789Z"
			script := "Write-Output 'fixture'\n"
			zero := 0
			calls := 0
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				if r.Method != "GET" || r.Header.Get("Authorization") != "Bearer maintainer" {
					t.Error("unsafe recovery request")
				}
				if r.URL.Path == "/api/v1/fleet/hosts/42" {
					at := enrollment
					if scenario == "changed-enrollment" {
						at = "2026-10-02T00:00:00Z"
					}
					if scenario == "missing-enrollment" {
						at = ""
					}
					_ = json.NewEncoder(w).Encode(map[string]any{"host": map[string]any{"id": 42, "uuid": "host-42", "platform": "windows", "last_enrolled_at": at}})
					return
				}
				if r.URL.Path != "/api/v1/fleet/scripts/results/execution-42" {
					t.Error("wrong original execution path")
				}
				at := "2026-10-08T12:00:01Z"
				if scenario == "same-second-before-request" {
					at = "2026-10-08T12:00:00Z"
				}
				_ = json.NewEncoder(w).Encode(windowsResult{HostID: 42, ExecutionID: "execution-42", Script: script + "\n# Collection nonce: original-command\n", ExitCode: &zero, CreatedAt: at})
			}))
			defer srv.Close()
			client, _ := NewClient(srv.URL, "maintainer", srv.Client(), time.Second)
			trust := strings.Repeat("a", 64)
			scriptHash := sha256.Sum256([]byte(script))
			binding := fmt.Sprintf("%s\x00%d\x00%s\x00%s\x00%s\x00%s\x00%s\x00%s", srv.URL, 42, "host-42", enrollment, enrollment, trust, "windows", hex.EncodeToString(scriptHash[:]))
			key := sha256.Sum256([]byte(binding))
			r := reservation{Key: hex.EncodeToString(key[:]), UUID: "original-command", HostID: 42, HostUUID: "host-42", EnrolledAt: 1790812800.123456789, FleetEnrolledAt: enrollment, CreatedAt: 1791460800.75, Transport: "windows", Trust: trust, Script: script + "\n# Collection nonce: original-command\n", ExecutionID: "execution-42"}
			var hints []string
			if scenario == "hint-terminal" {
				r.ExecutionID = ""
				hints = []string{"execution-42"}
			}
			raw, _ := json.Marshal(r)
			proof, e := client.RecoverCollectionWork(context.Background(), raw, nil, hints)
			good := scenario == "terminal" || scenario == "hint-terminal"
			if (e == nil) != good {
				t.Fatalf("proof=%+v error=%v", proof, e)
			}
			if good && (calls != 2 || proof.Outcome != "terminal" || proof.CommandUUID != r.UUID) {
				t.Fatal("lost bound original evidence", calls, proof)
			}
		})
	}
}
