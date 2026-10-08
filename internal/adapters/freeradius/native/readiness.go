package native

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"slices"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/config"
)

// Readiness is observed by the running daemon, including current policy snapshot
// freshness and actual certificate validity. The maintenance caller supplies the
// expected shared policy/trust identities; HTTP success alone never permits restart.
type Readiness struct {
	ConfigSHA256 string `json:"config_sha256"`
	TrustSHA256  string `json:"trust_sha256"`
	ServerDNS    string `json:"server_dns"`
	Ready        bool   `json:"ready"`
}
type readinessProof struct {
	Nonce    string    `json:"nonce"`
	Observed int64     `json:"observed"`
	State    Readiness `json:"state"`
}

func healthMAC(key, data []byte) string {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(data)
	return hex.EncodeToString(mac.Sum(nil))
}
func equalMAC(a, b string) bool {
	x, e := hex.DecodeString(a)
	y, f := hex.DecodeString(b)
	return e == nil && f == nil && len(x) == 32 && hmac.Equal(x, y)
}
func validReadiness(s Readiness) bool {
	return regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(s.ConfigSHA256) && regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(s.TrustSHA256) && regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9.-]{0,252}$`).MatchString(s.ServerDNS)
}
func ReadinessHandler(secret []byte, peers []string, observe func(context.Context) (Readiness, error)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, _, e := net.SplitHostPort(r.RemoteAddr)
		nonce := r.Header.Get("X-Cloud8021x-Nonce")
		if len(secret) < 32 || len(secret) > 256 || observe == nil || e != nil || !slices.Contains(peers, host) || r.Method != http.MethodGet || r.URL.Path != "/ready" || r.URL.RawQuery != "" || !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(nonce) || !equalMAC(r.Header.Get("X-Cloud8021x-MAC"), healthMAC(secret, []byte("request:"+nonce))) {
			http.Error(w, "unavailable", http.StatusForbidden)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), time.Second)
		defer cancel()
		state, e := observe(ctx)
		if e != nil || !validReadiness(state) {
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
			return
		}
		data, e := json.Marshal(readinessProof{Nonce: nonce, Observed: time.Now().Unix(), State: state})
		if e != nil {
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Cloud8021x-MAC", healthMAC(secret, data))
		_, _ = w.Write(data)
	})
}
func ProbeReadiness(ctx context.Context, endpoint string, secret []byte, expected Readiness) error {
	u, e := url.Parse(endpoint)
	if e != nil {
		return errors.New("invalid peer readiness endpoint")
	}
	ip, e := netip.ParseAddr(u.Hostname())
	if e != nil || (!ip.IsPrivate() && !ip.IsLoopback()) || u.Scheme != "http" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/ready") || len(secret) < 32 || len(secret) > 256 || !validReadiness(expected) {
		return errors.New("invalid protected peer readiness parameters")
	}
	var nonce [32]byte
	if _, e = rand.Read(nonce[:]); e != nil {
		return e
	}
	challenge := hex.EncodeToString(nonce[:])
	u.Path = "/ready"
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	request, e := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if e != nil {
		return errors.New("invalid peer request")
	}
	request.Header.Set("X-Cloud8021x-Nonce", challenge)
	request.Header.Set("X-Cloud8021x-MAC", healthMAC(secret, []byte("request:"+challenge)))
	client := &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true}, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("peer redirects refused") }}
	response, e := client.Do(request)
	if e != nil {
		return errors.New("peer readiness unavailable")
	}
	defer func() { _ = response.Body.Close() }()
	data, e := io.ReadAll(io.LimitReader(response.Body, 4097))
	if e != nil || len(data) > 4096 || response.StatusCode != 200 || !equalMAC(response.Header.Get("X-Cloud8021x-MAC"), healthMAC(secret, data)) {
		return errors.New("peer readiness authentication failed")
	}
	var proof readinessProof
	if json.Unmarshal(data, &proof) != nil || proof.Nonce != challenge || time.Now().Unix()-proof.Observed > 5 || proof.Observed > time.Now().Unix()+1 || !proof.State.Ready || proof.State.ConfigSHA256 != expected.ConfigSHA256 || proof.State.TrustSHA256 != expected.TrustSHA256 || proof.State.ServerDNS != expected.ServerDNS {
		return errors.New("peer policy or certificate readiness rejected")
	}
	return nil
}

// ExpectedReadiness excludes node-local addresses and includes all shared policy,
// source and enrollment settings. The caller supplies the same prepared public
// EC/RSA trust bundle consumed by RADIUS and managed certificate collection.
func ExpectedReadiness(cfg config.Config, trust []byte) (Readiness, error) {
	if len(trust) == 0 {
		return Readiness{}, errors.New("shared client trust unavailable")
	}
	input := struct {
		Policy    config.Policy
		Inventory config.Inventory
		Clients   []config.RadiusClient
		Locations []config.Location
		Bindings  []config.SourceBinding
		MaxAge    time.Duration
	}{cfg.Policy, cfg.Inventory, cfg.RadiusClients, cfg.Network.Locations, cfg.Network.Discovery.Bindings, cfg.Network.Discovery.MaxAge}
	data, e := json.Marshal(input)
	if e != nil {
		return Readiness{}, e
	}
	policy := sha256.Sum256(data)
	roots := sha256.Sum256(trust)
	return Readiness{ConfigSHA256: hex.EncodeToString(policy[:]), TrustSHA256: hex.EncodeToString(roots[:]), ServerDNS: cfg.Bootstrap.ServerDNS}, nil
}
