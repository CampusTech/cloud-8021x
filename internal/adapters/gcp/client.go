// Package gcp contains the fixed, root-only cloud boundary. It never consults
// ambient credential files, environment variables or caller-selected endpoints.
package gcp

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"hash/crc32"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var secretRE = regexp.MustCompile(`^projects/(?:[a-z][a-z0-9-]{4,62}|[1-9][0-9]*)/secrets/[A-Za-z0-9_-]{1,255}$`)
var versionRE = regexp.MustCompile(`^projects/(?:[a-z][a-z0-9-]{4,62}|[1-9][0-9]*)/secrets/[A-Za-z0-9_-]{1,255}/versions/[0-9]+$`)
var kmsRE = regexp.MustCompile(`^projects/(?:[a-z][a-z0-9-]{4,62}|[1-9][0-9]*)/locations/[a-z0-9-]+/keyRings/[A-Za-z0-9_-]+/cryptoKeys/[A-Za-z0-9_-]+/cryptoKeyVersions/[0-9]+$`)

type Client struct {
	projectID, projectNumber     string
	http                         *http.Client
	secretBase, sqlBase, kmsBase string
	token                        func(context.Context) (string, error)
}

func NewRoot(projectID, projectNumber string) (*Client, error) {
	if !regexp.MustCompile(`^[a-z][a-z0-9-]{4,62}$`).MatchString(projectID) || !regexp.MustCompile(`^[1-9][0-9]{5,19}$`).MatchString(projectNumber) {
		return nil, errors.New("pinned project ID and number required")
	}
	if os.Geteuid() != 0 {
		return nil, errors.New("cloud adapters require root")
	}
	hc := &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{Proxy: nil, MaxIdleConns: 4, IdleConnTimeout: time.Minute}, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("cloud redirects refused") }}
	c := &Client{projectID: projectID, projectNumber: projectNumber, http: hc, secretBase: "https://secretmanager.googleapis.com/v1", sqlBase: "https://sqladmin.googleapis.com/sql/v1beta4", kmsBase: "https://cloudkms.googleapis.com/v1"}
	c.token = func(ctx context.Context) (string, error) {
		r, e := http.NewRequestWithContext(ctx, http.MethodGet, "http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token", nil)
		if e != nil {
			return "", errors.New("metadata request invalid")
		}
		r.Header.Set("Metadata-Flavor", "Google")
		resp, e := hc.Do(r)
		if e != nil {
			return "", errors.New("root metadata credential unavailable")
		}
		defer func() { _ = resp.Body.Close() }()
		var v struct {
			AccessToken string `json:"access_token"`
		}
		if resp.StatusCode != 200 || resp.Header.Get("Metadata-Flavor") != "Google" || json.NewDecoder(io.LimitReader(resp.Body, 16384)).Decode(&v) != nil || v.AccessToken == "" {
			return "", errors.New("root metadata credential rejected")
		}
		return v.AccessToken, nil
	}
	return c, nil
}
func (c *Client) request(ctx context.Context, method, endpoint string, body any, out any) error {
	if e := ctx.Err(); e != nil {
		return e
	}
	var b []byte
	var e error
	if body != nil {
		b, e = json.Marshal(body)
		if e != nil {
			return errors.New("cloud request encoding failed")
		}
	}
	token, e := c.token(ctx)
	if e != nil {
		return e
	}
	r, e := http.NewRequestWithContext(ctx, method, endpoint, bytes.NewReader(b))
	if e != nil {
		return errors.New("cloud request invalid")
	}
	r.Header.Set("Authorization", "Bearer "+token)
	r.Header.Set("Content-Type", "application/json")
	resp, e := c.http.Do(r)
	if e != nil {
		return errors.New("cloud request failed or outcome uncertain")
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return errors.New("cloud API rejected request")
	}
	data, e := io.ReadAll(io.LimitReader(resp.Body, (2<<20)+1))
	if e != nil || len(data) > 2<<20 {
		return errors.New("cloud response exceeded bounds")
	}
	if out != nil && json.Unmarshal(data, out) != nil {
		return errors.New("cloud response invalid")
	}
	return nil
}
func (c *Client) Enabled(ctx context.Context, secret string) ([]string, error) {
	if !secretRE.MatchString(secret) || c.canonical(secret) == "" {
		return nil, errors.New("invalid exact secret resource")
	}
	var out struct {
		Versions      []struct{ Name, State string }
		NextPageToken string
	}
	u := c.secretBase + "/" + secret + "/versions?filter=" + url.QueryEscape("state=ENABLED") + "&pageSize=100"
	if e := c.request(ctx, http.MethodGet, u, nil, &out); e != nil {
		return nil, e
	}
	if len(out.Versions) > 100 {
		return nil, errors.New("secret version page exceeds requested bound")
	}
	v := []string{}
	for _, x := range out.Versions {
		if !versionRE.MatchString(x.Name) || !strings.HasPrefix(c.canonical(x.Name), c.canonical(secret)+"/versions/") || x.State != "ENABLED" {
			return nil, errors.New("invalid enabled secret version")
		}
		v = append(v, x.Name)
	}
	if len(v) == 0 && out.NextPageToken != "" {
		return nil, errors.New("ambiguous empty secret page")
	}
	return v, nil
}
func (c *Client) Access(ctx context.Context, version string) ([]byte, error) {
	if !versionRE.MatchString(version) || c.canonical(version) == "" {
		return nil, errors.New("invalid exact secret version")
	}
	var out struct {
		Name    string
		Payload struct {
			Data       string
			DataCRC32C string `json:"dataCrc32c"`
		}
	}
	if e := c.request(ctx, http.MethodGet, c.secretBase+"/"+version+":access", nil, &out); e != nil {
		return nil, e
	}
	b, e := base64.StdEncoding.DecodeString(out.Payload.Data)
	if e != nil || len(b) == 0 || len(b) > 1<<20 {
		return nil, errors.New("secret payload invalid")
	}
	if c.canonical(out.Name) == "" || c.canonical(out.Name) != c.canonical(version) || out.Payload.DataCRC32C != crc(b) {
		return nil, errors.New("secret checksum mismatch")
	}
	return b, nil
}
func crc(b []byte) string {
	return strconv.FormatUint(uint64(crc32.Checksum(b, crc32.MakeTable(crc32.Castagnoli))), 10)
}
func (c *Client) Add(ctx context.Context, secret string, b []byte) (string, error) {
	if !secretRE.MatchString(secret) || c.canonical(secret) == "" || len(b) == 0 || len(b) > 1<<20 {
		return "", errors.New("invalid secret publication")
	}
	var out struct{ Name string }
	e := c.request(ctx, http.MethodPost, c.secretBase+"/"+secret+":addVersion", map[string]any{"payload": map[string]string{"data": base64.StdEncoding.EncodeToString(b), "dataCrc32c": crc(b)}}, &out)
	if e != nil {
		return "", e
	}
	if !versionRE.MatchString(out.Name) || !strings.HasPrefix(c.canonical(out.Name), c.canonical(secret)+"/versions/") {
		return "", errors.New("secret publication response invalid")
	}
	return out.Name, nil
}
func (c *Client) Latest(ctx context.Context, secret string) ([]byte, error) {
	v, e := c.Enabled(ctx, secret)
	if e != nil {
		return nil, e
	}
	if len(v) == 0 {
		return nil, errors.New("required secret has no enabled version")
	}
	return c.Access(ctx, v[0])
}
func (c *Client) VerifyInstanceCA(ctx context.Context, instance, pin string) error {
	parts := strings.Split(instance, ":")
	if len(parts) != 3 || !regexp.MustCompile(`^[a-z][a-z0-9-]+$`).MatchString(parts[0]) || !regexp.MustCompile(`^[a-z][a-z0-9-]+$`).MatchString(parts[2]) {
		return errors.New("invalid Cloud SQL instance")
	}
	var out struct {
		ConnectionName string `json:"connectionName"`
		ServerCAMode   string `json:"serverCaMode"`
		ServerCACert   struct {
			Cert string `json:"cert"`
		} `json:"serverCaCert"`
	}
	if e := c.request(ctx, http.MethodGet, c.sqlBase+"/projects/"+parts[0]+"/instances/"+parts[2], nil, &out); e != nil {
		return e
	}
	sum := sha256.Sum256([]byte(out.ServerCACert.Cert))
	if out.ConnectionName != instance || out.ServerCAMode != "GOOGLE_MANAGED_INTERNAL_CA" || hex.EncodeToString(sum[:]) != pin {
		return errors.New("cloud SQL instance CA identity or pin mismatch")
	}
	return nil
}

type Signer struct {
	client   *Client
	ctx      context.Context
	resource string
	public   crypto.PublicKey
	hash     crypto.Hash
}

func (c *Client) Signer(ctx context.Context, resource string) (*Signer, error) {
	resource = strings.TrimPrefix(resource, "cloudkms:")
	if !kmsRE.MatchString(resource) || c.canonical(resource) == "" {
		return nil, errors.New("invalid pinned KMS key version")
	}
	var out struct {
		Name      string `json:"name"`
		PEM       string `json:"pem"`
		Algorithm string `json:"algorithm"`
		PEMCRC32C string `json:"pemCrc32c"`
	}
	if e := c.request(ctx, http.MethodGet, c.kmsBase+"/"+resource+"/publicKey", nil, &out); e != nil {
		return nil, e
	}
	if c.canonical(out.Name) == "" || c.canonical(out.Name) != c.canonical(resource) || out.PEMCRC32C != crc([]byte(out.PEM)) {
		return nil, errors.New("KMS public key checksum mismatch")
	}
	b, _ := pem.Decode([]byte(out.PEM))
	if b == nil {
		return nil, errors.New("KMS public key invalid")
	}
	pub, e := x509.ParsePKIXPublicKey(b.Bytes)
	if e != nil {
		return nil, errors.New("KMS public key invalid")
	}
	if out.Algorithm != "EC_SIGN_P256_SHA256" && out.Algorithm != "RSA_SIGN_PKCS1_4096_SHA256" && out.Algorithm != "RSA_SIGN_PKCS1_3072_SHA256" && out.Algorithm != "RSA_SIGN_PKCS1_2048_SHA256" {
		return nil, errors.New("unsupported pinned KMS signer algorithm")
	}
	return &Signer{client: c, ctx: ctx, resource: resource, public: pub, hash: crypto.SHA256}, nil
}
func (s *Signer) Public() crypto.PublicKey { return s.public }
func (s *Signer) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if opts.HashFunc() != s.hash || len(digest) != 32 {
		return nil, errors.New("KMS signing digest rejected")
	}
	var out struct {
		Signature            string
		SignatureCRC32C      string `json:"signatureCrc32c"`
		VerifiedDigestCRC32C bool   `json:"verifiedDigestCrc32c"`
		Name                 string
	}
	e := s.client.request(s.ctx, http.MethodPost, s.client.kmsBase+"/"+s.resource+":asymmetricSign", map[string]any{"digest": map[string]string{"sha256": base64.StdEncoding.EncodeToString(digest)}, "digestCrc32c": crc(digest)}, &out)
	if e != nil {
		return nil, e
	}
	sig, e := base64.StdEncoding.DecodeString(out.Signature)
	if e != nil || s.client.canonical(out.Name) == "" || s.client.canonical(out.Name) != s.client.canonical(s.resource) || !out.VerifiedDigestCRC32C || out.SignatureCRC32C != crc(sig) {
		return nil, errors.New("KMS signature integrity failed")
	}
	return sig, nil
}

// WithContext binds signing to the shared gate heartbeat/cancellation scope.
func (s *Signer) WithContext(ctx context.Context) crypto.Signer {
	copy := *s
	copy.ctx = ctx
	return &copy
}

// canonical recognizes only the protected configuration's explicit project pair.
// Terraform supplies the numeric project resource; arbitrary returned aliases
// never widen the caller's intended secret/key identity.
func (c *Client) canonical(resource string) string {
	parts := strings.Split(resource, "/")
	if len(parts) < 3 || parts[0] != "projects" {
		return ""
	}
	if c.projectID == "" && c.projectNumber == "" {
		return resource
	} // local fixtures
	if parts[1] != c.projectID && parts[1] != c.projectNumber {
		return ""
	}
	parts[1] = c.projectNumber
	return strings.Join(parts, "/")
}
