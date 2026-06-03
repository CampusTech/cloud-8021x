// Package fleet is a minimal client for looking up a host by hardware serial.
// Distinguishes three outcomes the authorizer needs: found (enrolled host),
// not-found (nil host, nil error), and error (Fleet unreachable / 5xx / bad
// auth) — the last MUST propagate so the caller can fail closed.
package fleet

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

type Host struct {
	ID             int
	HardwareSerial string
	Platform       string
	Enrolled       bool
	Labels         []string
}

func (h *Host) HasLabel(name string) bool {
	for _, l := range h.Labels {
		if l == name {
			return true
		}
	}
	return false
}

type Client struct {
	base  string
	token string
	hc    *http.Client
}

func New(baseURL, token string, timeout time.Duration) *Client {
	return &Client{base: baseURL, token: token, hc: &http.Client{Timeout: timeout}}
}

type hostResponse struct {
	Host *struct {
		ID             int    `json:"id"`
		HardwareSerial string `json:"hardware_serial"`
		Platform       string `json:"platform"`
		Labels         []struct {
			Name string `json:"name"`
		} `json:"labels"`
	} `json:"host"`
}

// LookupHostBySerial returns (host, nil) if enrolled, (nil, nil) if no such
// host (404), or (nil, error) on any transport/non-2xx/parse failure.
func (c *Client) LookupHostBySerial(ctx context.Context, serial string) (*Host, error) {
	u := fmt.Sprintf("%s/api/latest/fleet/hosts/identifier/%s", c.base, url.PathEscape(serial))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	switch {
	case resp.StatusCode == http.StatusNotFound:
		return nil, nil
	case resp.StatusCode < 200 || resp.StatusCode >= 300:
		return nil, fmt.Errorf("fleet returned status %d", resp.StatusCode)
	}
	var hr hostResponse
	if err := json.NewDecoder(resp.Body).Decode(&hr); err != nil {
		return nil, err
	}
	if hr.Host == nil {
		return nil, nil
	}
	h := &Host{ID: hr.Host.ID, HardwareSerial: hr.Host.HardwareSerial, Platform: hr.Host.Platform, Enrolled: true}
	for _, l := range hr.Host.Labels {
		h.Labels = append(h.Labels, l.Name)
	}
	return h, nil
}
