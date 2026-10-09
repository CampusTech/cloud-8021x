package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/adapters/fleet"
	"github.com/CampusTech/cloud-8021x/internal/migration"
)

func fleetFixture(t *testing.T) *fixture {
	t.Helper()
	f := testFixture(t)
	const config = `{"schema":1,"project_id":"task11-fixture","project_number":"111222333444","secrets":{},"keys":{},"routes":[],"contract":{"schema":1,"gate":"primitive-contract","application_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","fleet":{"authorization":"Bearer task11-fleet","hosts":[{"id":1,"uuid":"11111111-2222-4333-8444-555555555555","platform":"darwin","os_version":"15.0","team_id":1,"last_mdm_enrolled_at":"2026-10-08T10:00:00Z","last_enrolled_at":"2026-10-07T10:00:00Z","mdm":{"enrollment_status":"On","profiles":[]},"labels":[{"name":"task11-allowed"}]}],"commands":[{"command_uuid":"task11-retained-command-0001","host_id":1,"host_uuid":"11111111-2222-4333-8444-555555555555","created_at":"2026-10-08T10:00:00Z","request_type":"CertificateList"}]}}}`
	if err := json.Unmarshal([]byte(config), &f.config); err != nil {
		t.Fatal(err)
	}
	return f
}
func fleetRequest(t *testing.T, f *fixture, method, path, body string, want int, peers ...string) map[string]any {
	t.Helper()
	r := httptest.NewRequest(method, "https://fleet.task11.test"+path, strings.NewReader(body))
	if f.config.Contract.Gate == "installed-traffic" {
		r.RemoteAddr = "10.203.11.21:4321"
	}
	if len(peers) > 0 {
		r.RemoteAddr = peers[0] + ":4321"
	}
	r.Header.Set("Authorization", "Bearer task11-fleet")
	w := httptest.NewRecorder()
	f.ServeHTTP(w, r)
	if w.Code != want {
		t.Fatalf("%s %s: got %d want %d: %s", method, path, w.Code, want, w.Body.String())
	}
	var out map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	return out
}
func TestFleetRetainedPendingAndBoundedInventory(t *testing.T) {
	f := fleetFixture(t)
	result := fleetRequest(t, f, "GET", "/api/v1/fleet/commands/results?command_uuid=task11-retained-command-0001", "", 200)
	rows := result["results"].([]any)
	if len(rows) != 1 || rows[0].(map[string]any)["status"] != "NotNow" {
		t.Fatal("retained command must start unresolved")
	}
	page := fleetRequest(t, f, "GET", "/api/v1/fleet/hosts?device_mapping=true&page=0&per_page=1&populate_labels=true", "", 200)
	if len(page["hosts"].([]any)) != 1 {
		t.Fatal("first real inventory page missing")
	}
	page = fleetRequest(t, f, "GET", "/api/v1/fleet/hosts?device_mapping=true&page=1&per_page=1&populate_labels=true", "", 200)
	if len(page["hosts"].([]any)) != 0 {
		t.Fatal("pagination did not terminate")
	}
	fleetRequest(t, f, "GET", "/api/v1/fleet/commands/results?command_uuid=foreign", "", 404)
	fleetRequest(t, f, "POST", "/api/v1/fleet/commands/run", `{}`, 403)
}

// Use the actual product client over an in-process HTTP transport: no endpoint
// changes in shipping code and no host listener/network required.
type fixtureTransport struct{ f *fixture }

func (transport fixtureTransport) RoundTrip(r *http.Request) (response *http.Response, err error) {
	defer func() {
		if value := recover(); value != nil {
			if value == http.ErrAbortHandler {
				response = nil
				err = io.ErrUnexpectedEOF
			} else {
				panic(value)
			}
		}
	}()
	w := httptest.NewRecorder()
	transport.f.ServeHTTP(w, r)
	return w.Result(), nil
}
func TestActualFleetRecoveryMissingRemainsUncertainAndNeverReposts(t *testing.T) {
	f := fleetFixture(t)
	client, err := fleet.NewClient("https://fleet.task11.test", "task11-fleet", &http.Client{Transport: fixtureTransport{f}}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	host := f.config.Contract.Fleet.Hosts[0]
	at, err := time.Parse(time.RFC3339, host.MDMEnrolledAt)
	if err != nil {
		t.Fatal(err)
	}
	enrolled, _ := json.Marshal(host.EnrolledAt)
	stamp := strconv.FormatInt(at.Unix(), 10)
	binding := []json.RawMessage{json.RawMessage(`1`), json.RawMessage(stamp), enrolled}
	legacy := migration.LegacyCertificateHost{Binding: binding, Platform: "darwin"}
	command := migration.LegacyCommand{UUID: "task11-retained-command-0001", CreatedAt: json.Number(stamp), Hosts: map[string][]json.RawMessage{host.UUID: binding}}
	for _, scenario := range []string{"fleet-pending", "fleet-missing", "fleet-terminal"} {
		if err = f.advanceScenario(scenario, command.UUID); err != nil {
			t.Fatal(err)
		}
		proof, e := client.RecoverLegacyCommand(context.Background(), "https://fleet.task11.test", host.UUID, legacy, command, "")
		if (e == nil) != (scenario == "fleet-terminal") {
			t.Fatalf("%s: proof=%+v error=%v", scenario, proof, e)
		}
	}
	for _, event := range f.remote.Events {
		if event.Method != "GET" {
			t.Fatal("recovery repeated remote mutation")
		}
	}
	if f.remote.Commands[command.UUID].Posts != 0 {
		t.Fatal("retained command was reissued")
	}
}
func TestFleetAcceptedResponseLossRetainsExactCommandAndDetectsRepeat(t *testing.T) {
	f := fleetFixture(t)
	f.phase = "active"
	if err := f.advanceScenario("fleet-uncertain", ""); err != nil {
		t.Fatal(err)
	}
	id := "actual-new-nonce"
	command := base64.StdEncoding.EncodeToString([]byte(applePrefix + id + appleSuffix))
	payload, _ := json.Marshal(map[string]any{"command": command, "host_uuids": []string{f.config.Contract.Fleet.Hosts[0].UUID}})
	request := httptest.NewRequest("POST", "https://fleet.task11.test/api/v1/fleet/commands/run", bytes.NewReader(payload))
	request.Header.Set("Authorization", "Bearer task11-fleet")
	response, err := (fixtureTransport{f}).RoundTrip(request)
	if err == nil || response != nil {
		t.Fatal("uncertain accepted POST returned success")
	}
	accepted := f.remote.Commands[id]
	if accepted.Command != command || accepted.BodySHA256 != digestBytes(payload) || accepted.Posts != 1 {
		t.Fatal("lost exact accepted request provenance")
	}
	fleetRequest(t, f, "POST", "/api/v1/fleet/commands/run", string(payload), 409)
	if f.remote.Commands[id].Posts != 2 {
		t.Fatal("repeated POST not visible to verifier")
	}
}

func TestFleetWindowsUncertainPostRetainsActualScriptAndNonce(t *testing.T) {
	f := fleetFixture(t)
	f.phase = "active"
	f.config.Contract.Fleet.Hosts[0].Platform = "windows"
	f.config.Contract.Fleet.Hosts[0].ScriptsEnabled = true
	if err := f.advanceScenario("fleet-uncertain", ""); err != nil {
		t.Fatal(err)
	}
	const nonce = "12345678-1234-4234-8234-123456789012"
	const script = "Write-Output 'actual SYSTEM collection'\n# Collection nonce: " + nonce + "\n"
	payload, _ := json.Marshal(map[string]any{"host_id": 1, "script_contents": script})
	request := httptest.NewRequest("POST", "https://fleet.task11.test/api/v1/fleet/scripts/run", bytes.NewReader(payload))
	request.Header.Set("Authorization", "Bearer task11-fleet")
	if response, err := (fixtureTransport{f}).RoundTrip(request); err == nil || response != nil {
		t.Fatal("accepted lost response was acknowledged")
	}
	c := f.remote.Commands[nonce]
	if c.Script != script || c.Posts != 1 || c.BodySHA256 != digestBytes(payload) || c.ExecutionID == "" {
		t.Fatal("actual Windows request provenance lost")
	}
	for _, step := range []struct {
		name   string
		status int
	}{{"fleet-pending", 200}, {"fleet-missing", 404}, {"fleet-terminal", 200}} {
		if err := f.advanceScenario(step.name, nonce); err != nil {
			t.Fatal(err)
		}
		result := fleetRequest(t, f, "GET", "/api/v1/fleet/scripts/results/"+c.ExecutionID, "", step.status)
		if step.status == 200 && (result["script_contents"] != script || result["execution_id"] != c.ExecutionID) {
			t.Fatal("actual script result binding lost")
		}
	}
	if f.remote.Commands[nonce].Posts != 1 {
		t.Fatal("result recovery repeated submission")
	}
}
