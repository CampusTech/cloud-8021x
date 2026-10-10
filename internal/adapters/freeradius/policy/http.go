package policy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/domain"
	"golang.org/x/sys/unix"
)

type HTTPOptions struct {
	Token          []byte
	MaxConcurrency int
	MaxBodyBytes   int
	Timeout        time.Duration
	Service        DecisionService
}
type Handler struct {
	tokenHash [32]byte
	slots     chan struct{}
	maxBody   int64
	timeout   time.Duration
	service   DecisionService
}

func NewHandler(o HTTPOptions) (*Handler, error) {
	if len(o.Token) < 32 || len(o.Token) > 4096 || bytes.ContainsAny(o.Token, " \t\r\n\x00") || o.MaxConcurrency < 1 || o.MaxConcurrency > 1024 || o.MaxBodyBytes < 1 || o.MaxBodyBytes > 1<<20 || o.Timeout <= 0 || o.Timeout > 10*time.Second || o.Service == nil {
		return nil, errors.New("invalid local policy HTTP configuration")
	}
	return &Handler{tokenHash: sha256.Sum256(o.Token), slots: make(chan struct{}, o.MaxConcurrency), maxBody: int64(o.MaxBodyBytes), timeout: o.Timeout, service: o.Service}, nil
}
func readLocalToken(path string) ([]byte, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, errors.New("local policy token unavailable")
	}
	f := os.NewFile(uintptr(fd), path)
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Mode&0777 != 0600 || st.Nlink != 1 {
		_ = f.Close()
		return nil, errors.New("local policy bearer token must be a private regular file")
	}

	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, 4097))
	if err != nil || len(data) > 4096 {
		return nil, errors.New("local policy token invalid")
	}
	return bytes.TrimSpace(data), nil
}
func (h *Handler) Server(address string) *http.Server {
	return &http.Server{Addr: address, Handler: h, ReadHeaderTimeout: h.timeout, ReadTimeout: h.timeout, WriteTimeout: h.timeout + time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 8192}
}
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	deny := func(code int) { w.WriteHeader(code); _, _ = w.Write([]byte(`{}`)) }
	health := r.URL.Path == "/healthz" && r.URL.RawQuery == ""
	if r.URL.Path != "/authorize" && r.URL.Path != "/authorize/native" && !health {
		deny(http.StatusNotFound)
		return
	}
	if (!health && r.Method != http.MethodPost) || (health && r.Method != http.MethodGet) {
		deny(http.StatusMethodNotAllowed)
		return
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	ip, e := netip.ParseAddr(host)
	if err != nil || e != nil || !ip.IsLoopback() || ip.Zone() != "" {
		deny(http.StatusForbidden)
		return
	}
	headers := r.Header.Values("Authorization")
	if len(headers) != 1 || !strings.HasPrefix(headers[0], "Bearer ") {
		deny(http.StatusUnauthorized)
		return
	}
	token := strings.TrimPrefix(headers[0], "Bearer ")
	sum := sha256.Sum256([]byte(token))
	if subtle.ConstantTimeCompare(sum[:], h.tokenHash[:]) != 1 {
		deny(http.StatusUnauthorized)
		return
	}
	if health {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	content, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || content != "application/json" {
		deny(http.StatusUnsupportedMediaType)
		return
	}
	decisionStarted := false
	select {
	case h.slots <- struct{}{}:
		defer func() {
			if !decisionStarted {
				<-h.slots
			}
		}()
	default:
		deny(http.StatusServiceUnavailable)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()
	controller := http.NewResponseController(w)
	_ = controller.SetReadDeadline(time.Now().Add(h.timeout))
	_ = controller.SetWriteDeadline(time.Now().Add(h.timeout + time.Second))
	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, h.maxBody))
	if err != nil {
		var max *http.MaxBytesError
		if errors.As(err, &max) {
			deny(http.StatusRequestEntityTooLarge)
		} else {
			deny(http.StatusBadRequest)
		}
		return
	}
	var input Request
	if r.URL.Path == "/authorize/native" {
		input, err = decodeNative(data)
	} else {
		err = domain.DecodeJSONStrict(data, &input)
	}
	if err != nil {
		deny(http.StatusBadRequest)
		return
	}
	if ctx.Err() != nil {
		deny(http.StatusServiceUnavailable)
		return
	}
	type outcome struct {
		result Result
		err    error
	}
	completed := make(chan outcome, 1)
	decisionStarted = true
	go func() {
		defer func() { <-h.slots }()
		result, err := h.service.Decide(ctx, input)
		completed <- outcome{result, err}
	}()
	var result Result
	select {
	case value := <-completed:
		result, err = value.result, value.err
	case <-ctx.Done():
		deny(http.StatusServiceUnavailable)
		return
	}
	if ctx.Err() != nil {
		deny(http.StatusServiceUnavailable)
		return
	}
	if err != nil {
		deny(http.StatusForbidden)
		return
	}
	reply, err := Serialize(result)
	if err != nil {
		deny(http.StatusServiceUnavailable)
		return
	}
	payload, err := json.Marshal(reply)
	if err != nil || len(payload) > 8192 {
		deny(http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(payload)
}

// REST values preserve FreeRADIUS's native integer/string types and assignment operator.
type RESTAttribute struct {
	DoXlat bool   `json:"do_xlat"`
	Type   string `json:"type"`
	Value  []any  `json:"value"`
	Op     string `json:"op"`
}
type RESTReply map[string]RESTAttribute

func Serialize(r Result) (RESTReply, error) {
	out := RESTReply{}
	for _, attr := range r.Network.Attributes {
		if attr.VendorID != 0 || attr.VendorType != 0 || attr.Tag != nil {
			return nil, errors.New("unsupported FreeRADIUS network attribute dictionary mapping")
		}
		var name string
		switch attr.Code {
		case 64:
			name = "Tunnel-Type"
			if attr.Type != domain.IntegerValue || attr.Integer != 13 {
				return nil, errors.New("invalid Tunnel-Type")
			}
		case 65:
			name = "Tunnel-Medium-Type"
			if attr.Type != domain.IntegerValue || attr.Integer != 6 {
				return nil, errors.New("invalid Tunnel-Medium-Type")
			}
		case 81:
			name = "Tunnel-Private-Group-Id"
			if attr.Type != domain.StringValue || r.Decision.VLAN == nil || attr.String != strconv.Itoa(r.Decision.VLAN.ID) {
				return nil, errors.New("invalid VLAN serialization")
			}
		default:
			return nil, errors.New("protected or unknown network attribute")
		}
		key := "reply:" + name
		if _, ok := out[key]; ok {
			return nil, errors.New("duplicate network reply attribute")
		}
		value := any(attr.Integer)
		kind := "integer"
		if attr.Type == domain.StringValue {
			value = attr.String
			kind = "string"
		}
		out[key] = RESTAttribute{Type: kind, Value: []any{value}, Op: ":="}
	}
	if r.Decision.VLAN == nil && len(out) != 0 || r.Decision.VLAN != nil && len(out) != 3 {
		return nil, errors.New("network reply disagrees with policy VLAN")
	}
	if r.Class != "" {
		if len(r.Class) > 253 || !strings.HasPrefix(r.Class, "c8021x.1.") {
			return nil, errors.New("invalid Class output")
		}
		out["reply:Class"] = RESTAttribute{Type: "string", Value: []any{r.Class}, Op: ":="}
	}
	return out, nil
}
