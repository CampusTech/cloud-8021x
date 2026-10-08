// Package fleet implements inventory and optional managed collection using separate credentials.
package fleet

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/domain"
)

const MaxResponseBytes = 32 << 20

var errNotFound = errors.New("fleet object not found")

type Client struct {
	base, token string
	http        *http.Client
}

func NewClient(base, token string, hc *http.Client, timeout time.Duration) (*Client, error) {
	u, err := url.Parse(base)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") || strings.TrimSpace(token) == "" || strings.ContainsAny(token, "\r\n") || timeout <= 0 || timeout > time.Minute {
		return nil, errors.New("invalid Fleet endpoint, credential or timeout")
	}
	if hc == nil {
		hc = &http.Client{}
	}
	copy := *hc
	copy.Timeout = timeout
	copy.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &Client{base: strings.TrimRight(base, "/"), token: token, http: &copy}, nil
}
func (c *Client) request(ctx context.Context, method, path string, body, out any) error {
	if c == nil || !strings.HasPrefix(path, "/api/v1/fleet/") {
		return errors.New("invalid Fleet request")
	}
	var encoded []byte
	var err error
	if body != nil {
		encoded, err = json.Marshal(body)
		if err != nil {
			return errors.New("invalid Fleet request body")
		}
	}
	tries := 1
	if method == http.MethodGet {
		tries = 3
	}
	for attempt := 0; attempt < tries; attempt++ {
		req, err := http.NewRequestWithContext(ctx, method, c.base+path, bytes.NewReader(encoded))
		if err != nil {
			return errors.New("invalid Fleet request")
		}
		req.Header.Set("Authorization", "Bearer "+c.token)
		req.Header.Set("Content-Type", "application/json")
		response, err := c.http.Do(req)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return errors.New("fleet transport failed")
		}
		data, readErr := io.ReadAll(io.LimitReader(response.Body, MaxResponseBytes+1))
		_ = response.Body.Close()
		if response.StatusCode == 429 && attempt+1 < tries {
			delay := time.Duration(attempt+1) * 100 * time.Millisecond
			if raw := response.Header.Get("Retry-After"); raw != "" {
				seconds, e := strconv.Atoi(raw)
				if e != nil || seconds < 0 || seconds > 2 {
					return errors.New("fleet rate limit exceeds retry budget")
				}
				delay = time.Duration(seconds) * time.Second
			}
			timer := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				timer.Stop()
				return ctx.Err()
			case <-timer.C:
			}
			continue
		}
		if response.StatusCode == 404 {
			return errNotFound
		}
		if response.StatusCode < 200 || response.StatusCode >= 300 {
			return fmt.Errorf("fleet request failed (status %d)", response.StatusCode)
		}
		if readErr != nil || len(data) > MaxResponseBytes {
			return errors.New("fleet response exceeds bounds or read failed")
		}
		// Reject duplicate keys recursively while tolerating vendor-owned extra fields.
		var check any
		if err = domain.DecodeJSONStrict(data, &check); err != nil {
			return errors.New("invalid Fleet response JSON")
		}
		if err = json.Unmarshal(data, out); err != nil {
			return errors.New("invalid Fleet response schema")
		}
		return nil
	}
	return errors.New("fleet rate limit exhausted")
}
