package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

func TestSharedAPISourceActiveGreenPassiveByObservedPeer(t *testing.T) {
	f := fleetFixture(t)
	f.phase = "active"
	raw, _ := json.Marshal(f.config)
	var config map[string]any
	_ = json.Unmarshal(raw, &config)
	config["contract"].(map[string]any)["peers"] = map[string]any{"10.203.11.31": map[string]string{"role": "original-primary", "phase": "active"}, "10.203.11.21": map[string]string{"role": "green-primary", "phase": "passive"}}
	raw, _ = json.Marshal(config)
	if err := json.Unmarshal(raw, &f.config); err != nil {
		t.Fatal(err)
	}
	f.config.Secrets["projects/111222333444/secrets/radius-smallstep-server-cert"] = map[string]string{"1": base64.StdEncoding.EncodeToString([]byte("original"))}
	payload := `{"payload":{"data":"bmV3","dataCrc32c":"` + crcString([]byte("new")) + `"}}`
	for _, tc := range []struct {
		peer string
		want int
	}{{"10.203.11.21:4321", 403}, {"10.203.11.31:4321", 200}, {"10.203.11.40:4321", 403}} {
		request := httptest.NewRequest("POST", "https://secretmanager.googleapis.com/v1/projects/task11-fixture/secrets/radius-smallstep-server-cert:addVersion", strings.NewReader(payload))
		request.RemoteAddr = tc.peer
		request.Header.Set("Authorization", "Bearer "+token)
		request.Header.Set("X-Forwarded-For", "10.203.11.31")
		response := httptest.NewRecorder()
		f.ServeHTTP(response, request)
		if response.Code != tc.want {
			t.Fatalf("peer %s got %d want %d", tc.peer, response.Code, tc.want)
		}
	}
}

func TestInstalledSeedRequiresAllExactInitiallyPassiveGreenPeers(t *testing.T) {
	f := fleetFixture(t)
	f.config.Contract.Gate = "installed-traffic"
	if err := f.config.Contract.validate(); err == nil {
		t.Fatal("installed shared API accepted no peer attribution")
	}
}
func TestPeerHistoryRejectsPolicyWithoutControllerEvidence(t *testing.T) {
	f := fleetFixture(t)
	f.config.Contract.Peers = map[string]peerPolicy{"10.203.11.21": {Role: "green-primary", Phase: "passive"}}
	f.initializeRemote()
	f.remote.Peers["10.203.11.21"] = peerPolicy{Role: "green-primary", Phase: "active"}
	// A private-state policy edit must not be interpreted as recorded controller
	// authorization or actual installed activation evidence.
	if err := f.auditJournal(nil); err == nil {
		t.Fatal("unrecorded peer policy accepted")
	}
}

// The address override belongs to the in-memory transport, not an HTTP header
// or application input. gRPC must consume its actual connection peer context.
type addressedConn struct {
	net.Conn
	remote net.Addr
}

func (c addressedConn) RemoteAddr() net.Addr { return c.remote }

type addressedListener struct {
	net.Listener
	remote net.Addr
}

func (l addressedListener) Accept() (net.Conn, error) {
	c, e := l.Listener.Accept()
	if e != nil {
		return nil, e
	}
	return addressedConn{c, l.remote}, nil
}
func TestSharedAPIActualGRPCPeerSeparatesSigning(t *testing.T) {
	for _, tc := range []struct {
		ip, role, phase string
		want            codes.Code
	}{{"10.203.11.31", "original-primary", "active", codes.OK}, {"10.203.11.21", "green-primary", "passive", codes.PermissionDenied}, {"10.203.11.40", "", "", codes.Unauthenticated}} {
		t.Run(tc.ip, func(t *testing.T) {
			f := fleetFixture(t)
			f.phase = "active"
			f.config.Contract.Peers = map[string]peerPolicy{"10.203.11.31": {Role: "original-primary", Phase: "active"}, "10.203.11.21": {Role: "green-primary", Phase: "passive"}}
			listener := bufconn.Listen(1 << 20)
			server := grpc.NewServer(grpc.ForceServerCodec(wireCodec{}), grpc.UnknownServiceHandler(f.grpcHandler))
			done := make(chan error, 1)
			go func() {
				done <- server.Serve(addressedListener{listener, &net.TCPAddr{IP: net.ParseIP(tc.ip), Port: 4321}})
			}()
			t.Cleanup(func() { server.Stop(); _ = listener.Close(); <-done })
			conn, err := grpc.NewClient("passthrough:///fixture", grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return listener.Dial() }), grpc.WithDefaultCallOptions(grpc.ForceCodec(wireCodec{})))
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = conn.Close() }()
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			ctx = metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+token, "x-forwarded-for", "10.203.11.31")
			hash := sha256.Sum256([]byte("real synthetic signing request"))
			request := wire(bytesField(bytesField(nil, 1, []byte(testKey)), 3, bytesField(nil, 1, hash[:])))
			var response wire
			if err := conn.Invoke(ctx, kmsService+"AsymmetricSign", &request, &response); status.Code(err) != tc.want {
				t.Fatalf("observed peer returned %v want %v", err, tc.want)
			}
			if len(f.remote.Events) != 1 || f.remote.Events[0].PeerIP != tc.ip || f.remote.Events[0].PeerRole != tc.role {
				t.Fatal("lost actual gRPC caller attribution")
			}
			if err := f.auditPeerHistory(false); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestInstalledPassiveProofRejectsEvenDeniedMutationAttempt(t *testing.T) {
	f := fleetFixture(t)
	f.phase = "active"
	f.config.Contract.Peers = map[string]peerPolicy{"10.203.11.21": {Role: "green-primary", Phase: "passive"}, "10.203.11.22": {Role: "green-secondary", Phase: "passive"}}
	f.config.Secrets["projects/111222333444/secrets/radius-smallstep-server-cert"] = map[string]string{"1": base64.StdEncoding.EncodeToString([]byte("original"))}
	for _, ip := range []string{"10.203.11.21", "10.203.11.22"} {
		r := httptest.NewRequest("GET", "https://secretmanager.googleapis.com/v1/projects/task11-fixture/secrets/radius-smallstep-server-cert/versions/1:access", nil)
		r.RemoteAddr = ip + ":4321"
		r.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		f.ServeHTTP(w, r)
		if w.Code != 200 {
			t.Fatal("passive read failed")
		}
	}
	request := httptest.NewRequest("POST", "https://secretmanager.googleapis.com/v1/projects/task11-fixture/secrets/radius-smallstep-server-cert:addVersion", strings.NewReader(`{}`))
	request.RemoteAddr = "10.203.11.21:4321"
	request.Header.Set("Authorization", "Bearer "+token)
	response := httptest.NewRecorder()
	f.ServeHTTP(response, request)
	if response.Code != 403 {
		t.Fatal("passive mutation not denied")
	}
	if err := f.auditPeerHistory(true); err == nil {
		t.Fatal("denied passive mutation attempt accepted as zero-mutation proof")
	}
}
