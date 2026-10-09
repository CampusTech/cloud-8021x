// cloud-fixture is development infrastructure, never a release artifact.
package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"golang.org/x/sys/unix"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protowire"
)

const token = "task11-synthetic-token-not-a-cloud-credential"
const kmsService = "/google.cloud.kms.v1.KeyManagementService/"
const maxBody = 2 << 20

type route struct {
	Host          string          `json:"host"`
	Method        string          `json:"method"`
	Target        string          `json:"target"`
	Status        int             `json:"status"`
	Response      json.RawMessage `json:"response"`
	BodySHA256    string          `json:"body_sha256"`
	Mutation      bool            `json:"mutation"`
	Authorization string          `json:"authorization"`
}
type seed struct {
	Contract      *contractSeed                `json:"contract,omitempty"`
	Schema        int                          `json:"schema"`
	ProjectID     string                       `json:"project_id"`
	ProjectNumber string                       `json:"project_number"`
	Secrets       map[string]map[string]string `json:"secrets"`
	Keys          map[string]string            `json:"keys"`
	Routes        []route                      `json:"routes"`
}
type fixture struct {
	config             seed
	keys               map[string]crypto.Signer
	phase              string
	journal            io.Writer
	journalBytes       int64
	mu                 sync.Mutex
	remote             *remoteState
	seedSHA256         string
	stateRoot          string
	observation        json.RawMessage
	callerIP           string
	callerRole         string
	incompleteEvidence bool
}

func crc(data []byte) uint64       { return uint64(crc32.Checksum(data, crc32.MakeTable(crc32.Castagnoli))) }
func crcString(data []byte) string { return strconv.FormatUint(crc(data), 10) }
func strictJSON(data []byte, v any) error {
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.UseNumber()
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	var extra any
	if dec.Decode(&extra) != io.EOF {
		return errors.New("trailing JSON")
	}
	return nil
}
func (f *fixture) canonical(resource string) string {
	parts := strings.Split(resource, "/")
	if len(parts) < 3 || parts[0] != "projects" {
		return ""
	}
	if parts[1] != f.config.ProjectID && parts[1] != f.config.ProjectNumber {
		return ""
	}
	parts[1] = f.config.ProjectNumber
	return strings.Join(parts, "/")
}
func (f *fixture) record(protocol, method, target string, body []byte, code int) error {
	if f.config.Contract != nil {
		f.initializeRemote()
		return f.recordRemote(protocol, method, target, body, code)
	}
	sum := sha256.Sum256(body)
	entry, _ := json.Marshal(map[string]any{"time": time.Now().UTC().Format(time.RFC3339Nano), "phase": f.phase, "peer_ip": f.callerIP, "peer_role": f.callerRole, "protocol": protocol, "method": method, "target": target, "body_bytes": len(body), "body_sha256": hex.EncodeToString(sum[:]), "status": code})
	if len(target) > 4096 || f.journalBytes+int64(len(entry))+1 > 32<<20 {
		return errors.New("fixture journal bound reached")
	}
	n, err := f.journal.Write(append(entry, '\n'))
	f.journalBytes += int64(n)
	return err
}
func (f *fixture) public(resource string) (map[string]any, error) {
	key := f.keys[f.canonical(resource)]
	if key == nil {
		return nil, errors.New("unknown key")
	}
	der, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		return nil, err
	}
	public := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	algorithm := ""
	switch p := key.Public().(type) {
	case *ecdsa.PublicKey:
		if p.Curve.Params().Name == "P-256" {
			algorithm = "EC_SIGN_P256_SHA256"
		}
	case *rsa.PublicKey:
		algorithm = fmt.Sprintf("RSA_SIGN_PKCS1_%d_SHA256", p.N.BitLen())
	}
	switch algorithm {
	case "EC_SIGN_P256_SHA256", "RSA_SIGN_PKCS1_2048_SHA256", "RSA_SIGN_PKCS1_3072_SHA256", "RSA_SIGN_PKCS1_4096_SHA256":
	default:
		return nil, errors.New("unsupported fixture key")
	}
	return map[string]any{"name": f.canonical(resource), "pem": string(public), "pemCrc32c": crcString(public), "algorithm": algorithm}, nil
}
func (f *fixture) sign(resource string, digest []byte, checksum string) ([]byte, error) {
	key := f.keys[f.canonical(resource)]
	if f.phase != "active" || key == nil || len(digest) != 32 || checksum != crcString(digest) {
		return nil, errors.New("signing denied")
	}
	return key.Sign(rand.Reader, digest, crypto.SHA256)
}
func normalizedAuthority(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		return h
	}
	return host
}
func (f *fixture) dispatch(r *http.Request, body []byte) (int, any, string) {
	host := normalizedAuthority(r.Host)
	if host == "169.254.169.254" || host == "metadata.google.internal" {
		if r.Method != "GET" || r.Header.Get("Metadata-Flavor") != "Google" {
			return 403, map[string]string{"error": "metadata flavor required"}, "application/json"
		}
		switch r.URL.RequestURI() {
		case "/computeMetadata/v1/instance/service-accounts/default/token",
			"/computeMetadata/v1/instance/service-accounts/default/token?scopes=https%3A%2F%2Fwww.googleapis.com%2Fauth%2Fcloud-platform%2Chttps%3A%2F%2Fwww.googleapis.com%2Fauth%2Fcloudkms":
			return 200, map[string]any{"access_token": token, "expires_in": 3600, "token_type": "Bearer"}, "application/json"
		case "/computeMetadata/v1/project/project-id":
			return 200, f.config.ProjectID, "text/plain"
		case "/computeMetadata/v1/project/numeric-project-id":
			return 200, f.config.ProjectNumber, "text/plain"
		case "/computeMetadata/v1/instance/service-accounts/default/email":
			return 200, "fixture@" + f.config.ProjectID + ".iam.gserviceaccount.com", "text/plain"
		case "/computeMetadata/v1/instance/service-accounts/":
			return 200, "default/\n", "text/plain"
		case "/computeMetadata/v1/instance/service-accounts/default/scopes":
			return 200, "https://www.googleapis.com/auth/cloud-platform\n", "text/plain"
		}
		return 404, map[string]string{"error": "unlisted metadata path"}, "application/json"
	}
	if host == "secretmanager.googleapis.com" || host == "cloudkms.googleapis.com" || host == "sqladmin.googleapis.com" {
		if r.Header.Get("Authorization") != "Bearer "+token {
			return 401, map[string]string{"error": "synthetic bearer required"}, "application/json"
		}
	}
	f.initializeRemote()
	if f.config.Contract != nil && f.config.Contract.OTLP != nil && host == f.config.Contract.OTLP.Host {
		return f.intakeHTTP(r, body)
	}
	if host == "fleet.task11.test" && f.config.Contract != nil {
		return f.fleet(r, body)
	}
	if host == "secretmanager.googleapis.com" {
		f.initializeRemote()
		code, payload := f.secretManager(r, body)
		return code, payload, "application/json"
	}
	if host == "cloudkms.googleapis.com" && strings.HasPrefix(r.URL.Path, "/v1/") && r.URL.RawQuery == "" {
		resource := strings.TrimPrefix(r.URL.Path, "/v1/")
		if r.Method == "GET" && strings.HasSuffix(resource, "/publicKey") {
			if out, err := f.public(strings.TrimSuffix(resource, "/publicKey")); err == nil {
				return 200, out, "application/json"
			}
		}
		if r.Method == "POST" && strings.HasSuffix(resource, ":asymmetricSign") {
			var request struct {
				Digest struct {
					SHA256 string `json:"sha256"`
				} `json:"digest"`
				CRC string `json:"digestCrc32c"`
			}
			if strictJSON(body, &request) == nil {
				digest, err := base64.StdEncoding.DecodeString(request.Digest.SHA256)
				if err == nil {
					name := strings.TrimSuffix(resource, ":asymmetricSign")
					sig, err := f.sign(name, digest, request.CRC)
					if err == nil {
						return 200, map[string]any{"name": f.canonical(name), "signature": base64.StdEncoding.EncodeToString(sig), "signatureCrc32c": crcString(sig), "verifiedDigestCrc32c": true}, "application/json"
					}
				}
			}
			return 403, map[string]string{"error": "signing denied"}, "application/json"
		}
	}
	for _, route := range f.config.Routes {
		if host != route.Host || r.Method != route.Method || r.URL.RequestURI() != route.Target {
			continue
		}
		if route.Mutation && f.phase != "active" {
			return 403, map[string]string{"error": "passive mutation denied"}, "application/json"
		}
		if route.Authorization != "" && r.Header.Get("Authorization") != route.Authorization {
			return 401, map[string]string{"error": "fixture authorization denied"}, "application/json"
		}
		if route.BodySHA256 != "" {
			sum := sha256.Sum256(body)
			if route.BodySHA256 != hex.EncodeToString(sum[:]) {
				return 400, map[string]string{"error": "unexpected request bytes"}, "application/json"
			}
		}
		return route.Status, route.Response, "application/json"
	}
	return 404, map[string]string{"error": "unlisted fixture request"}, "application/json"
}
func (f *fixture) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	release, err := f.openRemote()
	if err != nil {
		http.Error(w, "persistent remote state unavailable", http.StatusServiceUnavailable)
		return
	}
	defer release()
	complete, err := f.beginTransportEvidence()
	if err != nil {
		http.Error(w, "transport evidence unavailable", http.StatusServiceUnavailable)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBody+1))
	if err != nil || len(body) > maxBody {
		http.Error(w, "request too large", http.StatusRequestEntityTooLarge)
		return
	}
	phase := f.phase
	defer func() { f.phase = phase }()
	if err := f.observedPeer(r.RemoteAddr); err != nil {
		f.observation = nil
		if err := f.record("http", r.Method, r.Host+r.URL.RequestURI(), body, 403); err == nil {
			_ = complete()
		}
		http.Error(w, "unrecognized remote peer", http.StatusForbidden)
		return
	}
	code, payload, kind := f.dispatch(r, body)
	f.observeResponse(r, payload)
	if err := f.record("http", r.Method, r.Host+r.URL.RequestURI(), body, code); err != nil {
		http.Error(w, "journal unavailable", http.StatusServiceUnavailable)
		return
	}
	if err := complete(); err != nil {
		http.Error(w, "transport evidence incomplete", http.StatusServiceUnavailable)
		return
	}
	if kind == "drop" {
		panic(http.ErrAbortHandler)
	}
	w.Header().Set("Content-Type", kind)
	w.Header().Set("Metadata-Flavor", "Google")
	w.WriteHeader(code)
	if kind == "text/plain" {
		_, _ = fmt.Fprint(w, payload)
		return
	}
	if kind == "application/x-protobuf" {
		_, _ = w.Write(payload.([]byte))
		return
	}
	_ = json.NewEncoder(w).Encode(payload)
}

// No added cloud SDK: these two unary wire contracts use existing protobuf/grpc.
// Field numbers: official kms v1.26.0 kmspb service/resources descriptors.
// This is not actual shipped step-ca interoperability evidence.
type wire []byte
type wireCodec struct{}

func (wireCodec) Name() string { return "proto" }
func (wireCodec) Marshal(v any) ([]byte, error) {
	p, ok := v.(*wire)
	if !ok {
		return nil, errors.New("nonfixture protobuf")
	}
	return *p, nil
}
func (wireCodec) Unmarshal(b []byte, v any) error {
	p, ok := v.(*wire)
	if !ok {
		return errors.New("nonfixture protobuf")
	}
	*p = append((*p)[:0], b...)
	return nil
}
func fields(b []byte) (map[protowire.Number][]byte, error) {
	out := map[protowire.Number][]byte{}
	for len(b) > 0 {
		number, kind, n := protowire.ConsumeTag(b)
		if n < 0 || kind != protowire.BytesType {
			return nil, errors.New("unexpected wire field")
		}
		b = b[n:]
		value, n := protowire.ConsumeBytes(b)
		if n < 0 || out[number] != nil {
			return nil, errors.New("duplicate or truncated wire field")
		}
		out[number] = value
		b = b[n:]
	}
	return out, nil
}
func bytesField(b []byte, n protowire.Number, v []byte) []byte {
	return protowire.AppendBytes(protowire.AppendTag(b, n, protowire.BytesType), v)
}
func intField(b []byte, n protowire.Number, v uint64) []byte {
	return protowire.AppendVarint(protowire.AppendTag(b, n, protowire.VarintType), v)
}
func (f *fixture) grpcCall(method string, input wire) (wire, error) {
	request, err := fields(input)
	if err != nil {
		return nil, err
	}
	name := string(request[1])
	if f.canonical(name) == "" {
		return nil, errors.New("unknown resource")
	}
	switch method {
	case kmsService + "GetPublicKey":
		if len(request) != 1 {
			return nil, errors.New("unexpected public key fields")
		}
		key, err := f.public(name)
		if err != nil {
			return nil, err
		}
		algorithms := map[string]uint64{"RSA_SIGN_PKCS1_2048_SHA256": 5, "RSA_SIGN_PKCS1_3072_SHA256": 6, "RSA_SIGN_PKCS1_4096_SHA256": 7, "EC_SIGN_P256_SHA256": 12}
		value := []byte(key["pem"].(string))
		out := bytesField(nil, 1, value)
		out = intField(out, 2, algorithms[key["algorithm"].(string)])
		out = bytesField(out, 3, intField(nil, 1, crc(value)))
		out = bytesField(out, 4, []byte(f.canonical(name)))
		return intField(out, 5, 1), nil
	case kmsService + "AsymmetricSign":
		if len(request) != 2 && len(request) != 3 {
			return nil, errors.New("unexpected signing fields")
		}
		for n := range request {
			if n != 1 && n != 3 && n != 4 {
				return nil, errors.New("unexpected signing field")
			}
		}
		digestFields, err := fields(request[3])
		if err != nil || len(digestFields) != 1 {
			return nil, errors.New("unsupported digest")
		}
		digest := digestFields[1]
		verified := uint64(0)
		if wrapper, ok := request[4]; ok {
			n, k, size := protowire.ConsumeTag(wrapper)
			if n != 1 || k != protowire.VarintType || size < 0 {
				return nil, errors.New("bad digest CRC wrapper")
			}
			v, size2 := protowire.ConsumeVarint(wrapper[size:])
			if size2 < 0 || size+size2 != len(wrapper) || v != crc(digest) {
				return nil, errors.New("digest CRC mismatch")
			}
			verified = 1
		}
		sig, err := f.sign(name, digest, crcString(digest))
		if err != nil {
			return nil, err
		}
		out := bytesField(nil, 1, sig)
		out = bytesField(out, 2, intField(nil, 1, crc(sig)))
		out = intField(out, 3, verified)
		out = bytesField(out, 4, []byte(f.canonical(name)))
		return intField(out, 6, 1), nil
	default:
		return nil, errors.New("unlisted KMS method")
	}
}
func (f *fixture) grpcHandler(_ any, stream grpc.ServerStream) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	release, err := f.openRemote()
	if err != nil {
		return status.Error(codes.Unavailable, "persistent remote state unavailable")
	}
	defer release()
	f.observation = nil
	phase := f.phase
	defer func() { f.phase = phase }()
	address := ""
	if remote, ok := peer.FromContext(stream.Context()); ok && remote.Addr != nil {
		address = remote.Addr.String()
	}
	peerErr := f.observedPeer(address)
	method, _ := grpc.MethodFromServerStream(stream)
	md, _ := metadata.FromIncomingContext(stream.Context())
	complete, err := f.beginTransportEvidence()
	if err != nil {
		return status.Error(codes.Unavailable, "transport evidence unavailable")
	}
	var input wire
	if err := stream.RecvMsg(&input); err != nil {
		return err
	}
	code := codes.OK
	var output wire
	var callErr error
	if values := md.Get("authorization"); peerErr != nil || len(values) != 1 || values[0] != "Bearer "+token {
		code = codes.Unauthenticated
	} else {
		output, callErr = f.grpcCall(method, input)
		if callErr != nil {
			code = codes.PermissionDenied
		}
	}
	if err := f.record("grpc", "POST", method, input, int(code)); err != nil {
		return status.Error(codes.ResourceExhausted, "fixture journal unavailable")
	}
	if err := complete(); err != nil {
		return status.Error(codes.Unavailable, "transport evidence incomplete")
	}
	if code != codes.OK {
		return status.Error(code, "fixture request denied")
	}
	return stream.SendMsg(&output)
}
func loadFixture(root, phase string, journal io.Writer) (*fixture, error) {
	data, err := privateRead(filepath.Join(root, "seed.json"))
	if err != nil {
		return nil, err
	}
	var config seed
	if len(data) > maxBody || strictJSON(data, &config) != nil || config.Schema != 1 || !strings.HasPrefix(config.ProjectID, "task11-") || config.ProjectNumber != "111222333444" {
		return nil, errors.New("invalid synthetic seed")
	}
	if err := config.Contract.validate(); err != nil {
		return nil, err
	}
	f := &fixture{seedSHA256: digestBytes(data), stateRoot: root, config: config, keys: map[string]crypto.Signer{}, phase: phase, journal: journal}
	for resource, file := range config.Keys {
		if resource != f.canonical(resource) || filepath.Base(file) != file {
			return nil, errors.New("key resource/path rejected")
		}
		info, err := os.Lstat(filepath.Join(root, file))
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
			return nil, errors.New("private fixture key mode rejected")
		}
		data, err := os.ReadFile(filepath.Join(root, file))
		if err != nil {
			return nil, err
		}
		block, _ := pem.Decode(data)
		if block == nil {
			return nil, errors.New("fixture key PEM rejected")
		}
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		signer, ok := key.(crypto.Signer)
		if !ok {
			return nil, errors.New("fixture key is not a signer")
		}
		f.keys[resource] = signer
	}
	for resource, versions := range config.Secrets {
		if resource != f.canonical(resource) || len(versions) != 1 {
			return nil, errors.New("seed requires one explicit enabled version per synthetic secret")
		}
		for version, value := range versions {
			n, err := strconv.ParseUint(version, 10, 64)
			if err != nil || n == 0 {
				return nil, errors.New("invalid secret version")
			}
			data, err := base64.StdEncoding.DecodeString(value)
			if err != nil || len(data) == 0 || len(data) > 1<<20 {
				return nil, errors.New("invalid secret payload")
			}
		}
	}
	seen := map[string]bool{}
	for _, r := range config.Routes {
		key := r.Host + " " + r.Method + " " + r.Target
		if seen[key] || r.Host == "" || r.Status < 100 || r.Status > 599 || !json.Valid(r.Response) || !strings.HasPrefix(r.Target, "/") || (r.Method != "GET" && !r.Mutation) {
			return nil, errors.New("invalid/duplicate explicit route")
		}
		seen[key] = true
	}
	return f, nil
}
func serve(root, address, phase string, meta bool) error {
	if runtime.GOOS != "linux" || os.Geteuid() != 0 || (phase != "passive" && phase != "active") || !filepath.IsAbs(root) {
		return errors.New("owned root Linux fixture required")
	}
	marker, err := os.ReadFile("/etc/cloud8021x-task11-fixture")
	if err != nil || string(marker) != "synthetic-only-v1\n" {
		return errors.New("guest fixture marker missing")
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil || host != "10.203.11.10" || port != "443" {
		return errors.New("only reserved internal TLS listener permitted")
	}
	journal, err := privateFile(filepath.Join(root, "journal.jsonl"), unix.O_CREAT|unix.O_APPEND|unix.O_WRONLY)
	if err != nil {
		return err
	}
	defer func() { _ = journal.Close() }()
	f, err := loadFixture(root, phase, journal)
	if err != nil {
		return err
	}
	if meta {
		return (&http.Server{Addr: "169.254.169.254:80", Handler: f, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, MaxHeaderBytes: 16 << 10}).ListenAndServe()
	}
	g := grpc.NewServer(grpc.ForceServerCodec(wireCodec{}), grpc.UnknownServiceHandler(f.grpcHandler), grpc.MaxRecvMsgSize(maxBody), grpc.MaxConcurrentStreams(16))
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor == 2 && strings.HasPrefix(r.Header.Get("Content-Type"), "application/grpc") {
			g.ServeHTTP(w, r)
		} else {
			f.ServeHTTP(w, r)
		}
	})
	server := &http.Server{Addr: address, Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 15 * time.Second, MaxHeaderBytes: 16 << 10, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12}}
	return server.ListenAndServeTLS(filepath.Join(root, "tls.pem"), filepath.Join(root, "tls.key"))
}
func main() {
	var root, address, phase string
	var meta bool
	cmd := &cobra.Command{Use: "cloud-fixture", SilenceUsage: true, RunE: func(_ *cobra.Command, _ []string) error { return serve(root, address, phase, meta) }}
	cmd.AddCommand(verifyCommand(), scenarioCommand(), passiveAuditCommand())
	cmd.Flags().StringVar(&root, "fixture-root", "", "owned synthetic input directory")
	cmd.Flags().StringVar(&address, "listen", "10.203.11.10:443", "fixture-internal TLS address")
	cmd.Flags().StringVar(&phase, "phase", "passive", "passive or active")
	cmd.Flags().BoolVar(&meta, "metadata", false, "serve only node-local synthetic metadata")
	if err := cmd.Execute(); err != nil {
		logrus.WithError(err).Error("cloud fixture failed")
		os.Exit(1)
	}
}
