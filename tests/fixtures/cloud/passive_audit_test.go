package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	"golang.org/x/sys/unix"
)

func passiveFixture(t *testing.T) *fixture {
	t.Helper()
	f := fleetFixture(t)
	f.phase = "active"
	f.config.Contract.Gate = "installed-traffic"
	f.config.Contract.Peers = map[string]peerPolicy{}
	for ip, role := range ownedPeerRoles {
		phase := "passive"
		if strings.HasPrefix(role, "original-") {
			phase = "active"
		}
		f.config.Contract.Peers[ip] = peerPolicy{Role: role, Phase: phase}
	}
	f.config.Secrets["projects/111222333444/secrets/radius-smallstep-server-cert"] = map[string]string{"1": base64.StdEncoding.EncodeToString([]byte("original"))}
	f.initializeRemote()
	f.seedSHA256 = f.remote.SeedSHA256
	return f
}
func deniedPassiveMutation(t *testing.T, f *fixture) {
	t.Helper()
	request := httptest.NewRequest("POST", "https://secretmanager.googleapis.com/v1/projects/task11-fixture/secrets/radius-smallstep-server-cert:addVersion", strings.NewReader(`{}`))
	request.RemoteAddr = "10.203.11.21:4321"
	request.Header.Set("Authorization", "Bearer "+token)
	response := httptest.NewRecorder()
	f.ServeHTTP(response, request)
	if response.Code != 403 {
		t.Fatal("passive mutation was not denied")
	}
}
func TestPassiveAuditCannotReuseGeneralHistoryAsPassiveProof(t *testing.T) {
	for _, mode := range []string{"active policy", "denied mutation", "unbound controller"} {
		t.Run(mode, func(t *testing.T) {
			f := passiveFixture(t)
			baseline, err := f.auditPassive("baseline", f.seedSHA256, "10.203.11.21", -1, "")
			if err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "active policy":
				if err := f.runScenario("peer-active", "", "10.203.11.21"); err != nil {
					t.Fatal(err)
				}
			case "denied mutation":
				deniedPassiveMutation(t, f)
			case "unbound controller":
				if err := f.recordRemote("controller", "SCENARIO", "invented-control", nil, 0); err != nil {
					t.Fatal(err)
				}
			}
			// The dedicated audit rejects cases the unchanged general history
			// checker cannot certify as a selected passive interval.
			if _, err := f.auditPassive("final", f.seedSHA256, "10.203.11.21", baseline.ToSequence, baseline.BaselineSHA256); err == nil {
				t.Fatal("invalid passive proof accepted")
			}
		})
	}
}

func newPrivatePassiveFixture(t *testing.T) (string, *fixture) {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	source := passiveFixture(t)
	raw, err := json.Marshal(source.config)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(root, "seed.json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(root, "journal.jsonl"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	return root, reopenPassiveFixture(t, root)
}
func reopenPassiveFixture(t *testing.T, root string) *fixture {
	t.Helper()
	journal, err := privateFile(filepath.Join(root, "journal.jsonl"), unix.O_APPEND|unix.O_WRONLY)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = journal.Close() })
	f, err := loadFixture(root, "active", journal)
	if err != nil {
		t.Fatal(err)
	}
	return f
}
func lockedPassiveAudit(t *testing.T, f *fixture, mode string, after int, baseline string) (passiveAuditResult, error) {
	t.Helper()
	release, err := f.openRemote()
	if err != nil {
		return passiveAuditResult{}, err
	}
	defer release()
	return f.auditPassive(mode, f.seedSHA256, "10.203.11.21", after, baseline)
}
func lockedScenario(t *testing.T, f *fixture, name, peer string) {
	t.Helper()
	release, err := f.openRemote()
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	if err = f.runScenario(name, "", peer); err != nil {
		t.Fatal(err)
	}
}
func TestPassiveAuditPrivatePreparedWindowCountsActualTraffic(t *testing.T) {
	root, f := newPrivatePassiveFixture(t)
	baseline, err := lockedPassiveAudit(t, f, "baseline", -1, "")
	if err != nil {
		t.Fatal(err)
	}
	if baseline.FromSequence != 0 || baseline.ToSequence != 0 || baseline.Events != 0 {
		t.Fatal("baseline invented history")
	}
	empty, err := lockedPassiveAudit(t, reopenPassiveFixture(t, root), "final", baseline.ToSequence, baseline.BaselineSHA256)
	if err != nil {
		t.Fatal(err)
	}
	if empty.Events != 0 || empty.ReadAttempts != 0 || empty.MutationAttempts != 0 {
		t.Fatal("empty passive interval invented traffic")
	}
	secretRequest(t, reopenPassiveFixture(t, root), "GET", "radius-smallstep-server-cert/versions/1:access", "", 200, "10.203.11.21")
	payload := `{"payload":{"data":"bmV3","dataCrc32c":"` + crcString([]byte("new")) + `"}}`
	secretRequest(t, reopenPassiveFixture(t, root), "POST", "radius-smallstep-server-cert:addVersion", payload, 200, "10.203.11.31")
	before, err := privateRead(filepath.Join(root, "journal.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	result, err := lockedPassiveAudit(t, reopenPassiveFixture(t, root), "final", baseline.ToSequence, baseline.BaselineSHA256)
	if err != nil {
		t.Fatal(err)
	}
	if result.ToSequence != 2 || result.Events != 1 || result.HTTPRequests != 1 || result.ReadAttempts != 1 || result.SuccessfulReads != 1 || result.OtherPeerEvents != 1 || result.MutationAttempts != 0 {
		t.Fatalf("incorrect actual counts: %+v", result)
	}
	after, err := privateRead(filepath.Join(root, "journal.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("read-only audit changed actual journal")
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	if len(encoded) > 2048 || bytes.Contains(encoded, []byte(token)) || bytes.Contains(encoded, []byte("observation")) || !shaPin.MatchString(result.EvidenceSHA256) {
		t.Fatal("unbounded or private result")
	}
}
func TestPassiveAuditPrivateDeactivatedWindowPermitsPriorActiveHistory(t *testing.T) {
	root, f := newPrivatePassiveFixture(t)
	prepared, err := lockedPassiveAudit(t, f, "baseline", -1, "")
	if err != nil {
		t.Fatal(err)
	}
	lockedScenario(t, reopenPassiveFixture(t, root), "peer-active", "10.203.11.21")
	payload := `{"payload":{"data":"bmV3","dataCrc32c":"` + crcString([]byte("new")) + `"}}`
	secretRequest(t, reopenPassiveFixture(t, root), "POST", "radius-smallstep-server-cert:addVersion", payload, 200, "10.203.11.21")
	if _, err = lockedPassiveAudit(t, reopenPassiveFixture(t, root), "baseline", -1, ""); err == nil {
		t.Fatal("active current peer accepted as passive baseline")
	}
	lockedScenario(t, reopenPassiveFixture(t, root), "peer-passive", "10.203.11.21")
	deactivated, err := lockedPassiveAudit(t, reopenPassiveFixture(t, root), "baseline", -1, "")
	if err != nil {
		t.Fatal(err)
	}
	if deactivated.ToSequence != 3 {
		t.Fatal("deactivation watermark did not use actual sequence")
	}
	if _, err = lockedPassiveAudit(t, reopenPassiveFixture(t, root), "final", prepared.ToSequence, prepared.BaselineSHA256); err == nil {
		t.Fatal("active period inside earlier window ignored")
	}
	result, err := lockedPassiveAudit(t, reopenPassiveFixture(t, root), "final", deactivated.ToSequence, deactivated.BaselineSHA256)
	if err != nil {
		t.Fatal(err)
	}
	if result.Events != 0 || result.FromSequence != 3 || result.ToSequence != 3 {
		t.Fatal("prior active traffic counted as passive window")
	}
	deniedPassiveMutation(t, reopenPassiveFixture(t, root))
	if _, err = lockedPassiveAudit(t, reopenPassiveFixture(t, root), "final", deactivated.ToSequence, deactivated.BaselineSHA256); err == nil {
		t.Fatal("persisted denied passive mutation accepted")
	}
}
func TestPassiveAuditRejectsUnboundSeedPeerCursorAndControls(t *testing.T) {
	for _, mode := range []string{"missing seed", "wrong seed", "foreign peer", "other peer baseline", "future cursor", "negative cursor", "wrong prefix", "active at cursor", "active transition without traffic", "foreign actual caller", "unbound known control"} {
		t.Run(mode, func(t *testing.T) {
			f := passiveFixture(t)
			baseline, err := f.auditPassive("baseline", f.seedSHA256, "10.203.11.21", -1, "")
			if err != nil {
				t.Fatal(err)
			}
			seedPin, peer, cursor, prefix := f.seedSHA256, "10.203.11.21", baseline.ToSequence, baseline.BaselineSHA256
			switch mode {
			case "missing seed":
				f.seedSHA256 = ""
			case "wrong seed":
				seedPin = strings.Repeat("b", 64)
			case "foreign peer":
				peer = "10.203.11.31"
			case "other peer baseline":
				peer = "10.203.11.22"
			case "future cursor":
				cursor = 1
			case "negative cursor":
				cursor = -1
			case "wrong prefix":
				prefix = strings.Repeat("b", 64)
			case "active at cursor":
				if err = f.runScenario("peer-active", "", "10.203.11.21"); err != nil {
					t.Fatal(err)
				}
				cursor = 1
				prefix, err = f.passivePrefix(seedPin, peer, cursor)
				if err != nil {
					t.Fatal(err)
				}
				if err = f.runScenario("peer-passive", "", "10.203.11.21"); err != nil {
					t.Fatal(err)
				}
			case "active transition without traffic":
				if err = f.runScenario("peer-active", "", "10.203.11.21"); err != nil {
					t.Fatal(err)
				}
				if err = f.runScenario("peer-passive", "", "10.203.11.21"); err != nil {
					t.Fatal(err)
				}
			case "foreign actual caller":
				request := httptest.NewRequest("GET", "https://secretmanager.googleapis.com/v1/projects/task11-fixture/secrets/radius-smallstep-server-cert/versions/1:access", nil)
				request.RemoteAddr = "10.203.11.40:4321"
				request.Header.Set("Authorization", "Bearer "+token)
				request.Header.Set("X-Forwarded-For", "10.203.11.21")
				response := httptest.NewRecorder()
				f.ServeHTTP(response, request)
				if response.Code != 403 {
					t.Fatal("foreign caller not denied")
				}
			case "unbound known control":
				if err = f.recordRemote("controller", "SCENARIO", "fleet-terminal", []byte("foreign-command"), 0); err != nil {
					t.Fatal(err)
				}
			}
			if _, err = f.auditPassive("final", seedPin, peer, cursor, prefix); err == nil {
				t.Fatal("unbound passive window accepted")
			}
		})
	}
}
func TestPassiveAuditRefusesPersistedJournalMismatch(t *testing.T) {
	root, f := newPrivatePassiveFixture(t)
	baseline, err := lockedPassiveAudit(t, f, "baseline", -1, "")
	if err != nil {
		t.Fatal(err)
	}
	secretRequest(t, reopenPassiveFixture(t, root), "GET", "radius-smallstep-server-cert/versions/1:access", "", 200, "10.203.11.21")
	if err = os.WriteFile(filepath.Join(root, "journal.jsonl"), []byte("{}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = lockedPassiveAudit(t, reopenPassiveFixture(t, root), "final", baseline.ToSequence, baseline.BaselineSHA256); err == nil {
		t.Fatal("actual journal/state mismatch ignored")
	}
}
func TestPassiveAuditCLIHasNoGateOrPathOverride(t *testing.T) {
	cmd := passiveAuditCommand()
	for _, name := range []string{"gate", "fixture-root", "state", "path"} {
		if cmd.Flags().Lookup(name) != nil {
			t.Fatalf("unreviewed override %s", name)
		}
	}
	for _, name := range []string{"seed-sha256", "peer", "after-sequence", "baseline-sha256"} {
		if cmd.Flags().Lookup(name) == nil {
			t.Fatalf("missing bound option %s", name)
		}
	}
}

func TestPassiveAuditRejectsKnownControlWithoutValidStateTransition(t *testing.T) {
	f := passiveFixture(t)
	id := f.config.Contract.Fleet.Commands[0].UUID
	if err := f.runScenario("fleet-terminal", id, ""); err != nil {
		t.Fatal(err)
	}
	// Exact argument hash alone cannot authorize reopening a terminal command;
	// the real scenario implementation refuses this state transition.
	if err := f.recordRemote("controller", "SCENARIO", "fleet-pending", []byte(id), 0); err != nil {
		t.Fatal(err)
	}
	if _, err := f.auditPassive("baseline", f.seedSHA256, "10.203.11.21", -1, ""); err == nil {
		t.Fatal("impossible known controller transition accepted")
	}
}
func TestPassiveAuditRejectsUnjournaledControlState(t *testing.T) {
	f := passiveFixture(t)
	f.remote.IntakeUnavailable = true
	if _, err := f.auditPassive("baseline", f.seedSHA256, "10.203.11.21", -1, ""); err == nil {
		t.Fatal("control state without journal accepted")
	}
}

func TestPassiveAuditAcceptsBoundOriginalCollectionControls(t *testing.T) {
	f := passiveFixture(t)
	baseline, err := f.auditPassive("baseline", f.seedSHA256, "10.203.11.21", -1, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"fleet-uncertain", "inventory-error", "inventory-ready", "intake-unavailable", "intake-ready"} {
		if err = f.runScenario(name, "", ""); err != nil {
			t.Fatal(err)
		}
	}
	const id = "original-accepted-before-result"
	raw, _ := json.Marshal(map[string]any{"command": base64.StdEncoding.EncodeToString([]byte(applePrefix + id + appleSuffix)), "host_uuids": []string{f.config.Contract.Fleet.Hosts[0].UUID}})
	request := httptest.NewRequest("POST", "https://fleet.task11.test/api/v1/fleet/commands/run", bytes.NewReader(raw))
	request.RemoteAddr = "10.203.11.31:4321"
	request.Header.Set("Authorization", "Bearer task11-fleet")
	if response, err := (fixtureTransport{f}).RoundTrip(request); err == nil || response != nil {
		t.Fatal("expected accepted uncertain original request")
	}
	for _, name := range []string{"fleet-pending", "fleet-missing", "fleet-terminal"} {
		if err = f.runScenario(name, id, ""); err != nil {
			t.Fatal(err)
		}
	}
	result, err := f.auditPassive("final", f.seedSHA256, "10.203.11.21", baseline.ToSequence, baseline.BaselineSHA256)
	if err != nil {
		t.Fatal(err)
	}
	if result.Events != 0 || result.ControlEvents != 8 || result.OtherPeerEvents != 1 {
		t.Fatalf("original collection attributed to green: %+v", result)
	}
}
func TestPassiveAuditActualGRPCReadAndDeniedSign(t *testing.T) {
	f := passiveFixture(t)
	baseline, err := f.auditPassive("baseline", f.seedSHA256, "10.203.11.21", -1, "")
	if err != nil {
		t.Fatal(err)
	}
	listener := bufconn.Listen(1 << 20)
	server := grpc.NewServer(grpc.ForceServerCodec(wireCodec{}), grpc.UnknownServiceHandler(f.grpcHandler))
	done := make(chan error, 1)
	go func() {
		done <- server.Serve(addressedListener{listener, &net.TCPAddr{IP: net.ParseIP("10.203.11.21"), Port: 4321}})
	}()
	t.Cleanup(func() { server.Stop(); _ = listener.Close(); <-done })
	connection, err := grpc.NewClient("passthrough:///fixture", grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return listener.Dial() }), grpc.WithDefaultCallOptions(grpc.ForceCodec(wireCodec{})))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = connection.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	ctx = metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+token)
	request := wire(bytesField(nil, 1, []byte(testKey)))
	var response wire
	if err = connection.Invoke(ctx, kmsService+"GetPublicKey", &request, &response); err != nil {
		t.Fatal(err)
	}
	result, err := f.auditPassive("final", f.seedSHA256, "10.203.11.21", baseline.ToSequence, baseline.BaselineSHA256)
	if err != nil {
		t.Fatal(err)
	}
	if result.GRPCRequests != 1 || result.ReadAttempts != 1 || result.SuccessfulReads != 1 || result.HTTPRequests != 0 {
		t.Fatal("actual gRPC read not counted")
	}
	digest := sha256.Sum256([]byte("passive attempted sign"))
	request = bytesField(request, 3, bytesField(nil, 1, digest[:]))
	if err = connection.Invoke(ctx, kmsService+"AsymmetricSign", &request, &response); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("passive signing was not denied: %v", err)
	}
	if _, err = f.auditPassive("final", f.seedSHA256, "10.203.11.21", baseline.ToSequence, baseline.BaselineSHA256); err == nil {
		t.Fatal("actual denied gRPC signing certified as passive")
	}
}
