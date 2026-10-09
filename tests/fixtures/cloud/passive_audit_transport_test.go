package main

import (
	"bytes"
	"context"
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
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

func TestPassiveAuditIncompleteHTTPTransport(t *testing.T) {
	for _, which := range []string{"oversized body", "oversized target", "exhausted journal"} {
		t.Run(which, func(t *testing.T) {
			root, f := newPrivatePassiveFixture(t)
			if which == "exhausted journal" {
				release, err := f.openRemote()
				if err != nil {
					t.Fatal(err)
				}
				var journal bytes.Buffer
				for i := 1; i <= 8192; i++ {
					event := remoteEvent{Sequence: i, Time: time.Now().UTC().Format(time.RFC3339Nano), Phase: "passive", Protocol: "http", Method: "GET", Target: "example.task11.test/read", BodySHA256: digestBytes(nil), Status: 404, PeerIP: "10.203.11.21", PeerRole: "green-primary"}
					f.remote.Events = append(f.remote.Events, event)
					raw, _ := json.Marshal(event)
					journal.Write(raw)
					journal.WriteByte('\n')
				}
				if err = os.WriteFile(filepath.Join(root, "journal.jsonl"), journal.Bytes(), 0600); err != nil {
					t.Fatal(err)
				}
				if err = f.commitRemote(); err != nil {
					t.Fatal(err)
				}
				release()
			}
			baseline, err := lockedPassiveAudit(t, reopenPassiveFixture(t, root), "baseline", -1, "")
			if err != nil {
				t.Fatal(err)
			}
			body, target := "{}", "https://secretmanager.googleapis.com/v1/projects/task11-fixture/secrets/radius-smallstep-server-cert:addVersion"
			if which == "oversized body" {
				body = strings.Repeat("x", maxBody+1)
			}
			if which == "oversized target" {
				target = "https://example.task11.test/" + strings.Repeat("x", 4097)
			}
			request := httptest.NewRequest("POST", target, strings.NewReader(body))
			request.RemoteAddr = "10.203.11.21:1234"
			response := httptest.NewRecorder()
			reopenPassiveFixture(t, root).ServeHTTP(response, request)
			if response.Code < 400 {
				t.Fatal("request not refused")
			}
			if _, err = lockedPassiveAudit(t, reopenPassiveFixture(t, root), "final", baseline.ToSequence, baseline.BaselineSHA256); err == nil {
				t.Fatal("incomplete HTTP evidence certified as passive")
			}
		})
	}
}

func TestPassiveAuditIncompleteGRPCTransport(t *testing.T) {
	root, f := newPrivatePassiveFixture(t)
	baseline, err := lockedPassiveAudit(t, f, "baseline", -1, "")
	if err != nil {
		t.Fatal(err)
	}
	listener := bufconn.Listen(1 << 20)
	server := grpc.NewServer(grpc.ForceServerCodec(wireCodec{}), grpc.UnknownServiceHandler(reopenPassiveFixture(t, root).grpcHandler), grpc.MaxRecvMsgSize(1024))
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
	request := wire(bytes.Repeat([]byte("x"), 2048))
	var response wire
	if err = connection.Invoke(ctx, kmsService+"AsymmetricSign", &request, &response); status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("expected actual receive size refusal: %v", err)
	}
	if _, err = lockedPassiveAudit(t, reopenPassiveFixture(t, root), "final", baseline.ToSequence, baseline.BaselineSHA256); err == nil {
		t.Fatal("incomplete gRPC evidence certified as passive")
	}
}

func TestPassiveAuditStaticRouteAuthority(t *testing.T) {
	for _, port := range []string{"", ":443"} {
		for _, mutation := range []bool{false, true} {
			name := port + " read"
			if mutation {
				name = port + " mutation"
			}
			t.Run(name, func(t *testing.T) {
				root, f := newPrivatePassiveFixture(t)
				f.config.Routes = []route{{Host: "example.task11.test", Method: "GET", Target: "/change?exact=1", Mutation: mutation, Status: 200, Response: json.RawMessage(`{}`)}}
				seed, _ := json.Marshal(f.config)
				if err := os.WriteFile(filepath.Join(root, "seed.json"), seed, 0600); err != nil {
					t.Fatal(err)
				}
				f = reopenPassiveFixture(t, root)
				baseline, err := lockedPassiveAudit(t, f, "baseline", -1, "")
				if err != nil {
					t.Fatal(err)
				}
				request := httptest.NewRequest("GET", "https://example.task11.test"+port+"/change?exact=1", nil)
				request.RemoteAddr = "10.203.11.21:1234"
				response := httptest.NewRecorder()
				f.ServeHTTP(response, request)
				expected := 200
				if mutation {
					expected = 403
				}
				if response.Code != expected {
					t.Fatalf("route status %d", response.Code)
				}
				result, err := lockedPassiveAudit(t, reopenPassiveFixture(t, root), "final", baseline.ToSequence, baseline.BaselineSHA256)
				if mutation && err == nil {
					t.Fatal("mutation GET certified as passive read")
				}
				if !mutation && (err != nil || result.ReadAttempts != 1 || result.SuccessfulReads != 1) {
					t.Fatalf("genuine read refused: %+v %v", result, err)
				}
			})
		}
	}
}

func TestPassiveAuditInterruptedTransportSentinel(t *testing.T) {
	root, f := newPrivatePassiveFixture(t)
	baseline, err := lockedPassiveAudit(t, f, "baseline", -1, "")
	if err != nil {
		t.Fatal(err)
	}
	release, err := f.openRemote()
	if err != nil {
		t.Fatal(err)
	}
	complete, err := f.beginTransportEvidence()
	if err != nil {
		t.Fatal(err)
	}
	sentinel := filepath.Join(root, incompleteEvidenceFile)
	before, err := privateRead(sentinel)
	if err != nil || len(before) > 128 {
		t.Fatalf("unbounded or unprotected sentinel: %v", err)
	}
	release() // Simulated interruption: never call this operation's completion.
	if _, err = lockedPassiveAudit(t, reopenPassiveFixture(t, root), "final", baseline.ToSequence, baseline.BaselineSHA256); err == nil {
		t.Fatal("interrupted transport certified")
	}
	request := httptest.NewRequest("GET", "https://example.task11.test/read", nil)
	request.RemoteAddr = "10.203.11.21:1234"
	response := httptest.NewRecorder()
	reopenPassiveFixture(t, root).ServeHTTP(response, request)
	if response.Code != 503 {
		t.Fatal("preexisting incomplete sentinel did not stop serving")
	}
	after, err := privateRead(sentinel)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("later operation replaced incomplete sentinel")
	}
	other := reopenPassiveFixture(t, root)
	if _, err = other.beginTransportEvidence(); err == nil {
		t.Fatal("exclusive sentinel create accepted preexisting file")
	}
	if err = os.Rename(sentinel, sentinel+".original"); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(sentinel, []byte("replacement"), 0600); err != nil {
		t.Fatal(err)
	}
	if err = complete(); err == nil {
		t.Fatal("old operation removed another inode")
	}
	if _, err = os.Stat(sentinel); err != nil {
		t.Fatal("replacement sentinel removed")
	}
}

func TestPassiveAuditStaticRouteExactQuery(t *testing.T) {
	root, f := newPrivatePassiveFixture(t)
	f.config.Routes = []route{{Host: "example.task11.test", Method: "GET", Target: "/change?exact=1", Mutation: true, Status: 200, Response: json.RawMessage(`{}`)}}
	seed, _ := json.Marshal(f.config)
	if err := os.WriteFile(filepath.Join(root, "seed.json"), seed, 0600); err != nil {
		t.Fatal(err)
	}
	f = reopenPassiveFixture(t, root)
	baseline, err := lockedPassiveAudit(t, f, "baseline", -1, "")
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest("GET", "https://example.task11.test:443/change?exact=2", nil)
	request.RemoteAddr = "10.203.11.21:1234"
	response := httptest.NewRecorder()
	f.ServeHTTP(response, request)
	if response.Code != 404 {
		t.Fatal("dispatcher normalized distinct query")
	}
	result, err := lockedPassiveAudit(t, reopenPassiveFixture(t, root), "final", baseline.ToSequence, baseline.BaselineSHA256)
	if err != nil || result.ReadAttempts != 1 || result.SuccessfulReads != 0 {
		t.Fatalf("audit changed exact query meaning: %+v %v", result, err)
	}
}
