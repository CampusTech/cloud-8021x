// Package httpjson implements bounded, credential-confined read-only controller calls.
package httpjson

import (
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
)

const MaxPages = 100
const MaxBytes = 8 << 20

var ErrPagination = errors.New("invalid or incomplete controller pagination")

type StatusError struct{ Code int }

func (e StatusError) Error() string { return fmt.Sprintf("controller HTTP %d", e.Code) }

type Client struct {
	base        *url.URL
	client      *http.Client
	header, key string
}

func New(base, header, key string, hc *http.Client, timeout time.Duration) (*Client, error) {
	u, err := url.Parse(base)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || key == "" || strings.ContainsAny(key, "\r\n") {
		return nil, errors.New("invalid controller configuration")
	}
	if timeout == 0 {
		timeout = 20 * time.Second
	}
	if timeout < time.Millisecond || timeout > time.Minute {
		return nil, errors.New("invalid controller timeout")
	}
	c := http.Client{}
	if hc != nil {
		c = *hc
	}
	c.Timeout = timeout
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &Client{base: u, client: &c, header: header, key: key}, nil
}
func (c *Client) URL(path string) string { return strings.TrimSuffix(c.base.String(), "/") + path }
func (c *Client) Get(ctx context.Context, target string, out any) (http.Header, error) {
	u, err := url.Parse(target)
	if err != nil || u.Scheme != c.base.Scheme || u.Host != c.base.Host || u.User != nil || u.Fragment != "" || !strings.HasPrefix(u.Path, strings.TrimSuffix(c.base.Path, "/")+"/") {
		return nil, errors.New("unsafe controller URL")
	}
	for attempt := 0; attempt < 3; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
		if err != nil {
			return nil, errors.New("invalid controller request")
		}
		req.Header.Set(c.header, c.key)
		req.Header.Set("Accept", "application/json")
		res, err := c.client.Do(req)
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			return nil, errors.New("controller request failed")
		}
		if res.StatusCode == 429 && attempt < 2 {
			wait := 100 * time.Millisecond
			if v, err := strconv.Atoi(res.Header.Get("Retry-After")); err == nil && v >= 0 {
				wait = time.Duration(v) * time.Second
			}
			if wait > 2*time.Second {
				wait = 2 * time.Second
			}
			_ = res.Body.Close()
			timer := time.NewTimer(wait)
			select {
			case <-ctx.Done():
				timer.Stop()
				return nil, ctx.Err()
			case <-timer.C:
			}
			continue
		}
		if res.StatusCode != 200 {
			_ = res.Body.Close()
			return nil, StatusError{res.StatusCode}
		}
		body, err := io.ReadAll(io.LimitReader(res.Body, MaxBytes+1))
		_ = res.Body.Close()
		if err != nil || len(body) > MaxBytes {
			return nil, errors.New("controller response exceeds bound or unavailable")
		}
		if err = json.Unmarshal(body, out); err != nil {
			return nil, errors.New("invalid controller JSON")
		}
		return res.Header, nil
	}
	return nil, errors.New("controller retry limit")
}

// Next accepts only a single same-origin, identical-path next URL. It never forwards
// credentials to redirects, a different API resource or a caller-supplied origin.
func Next(h http.Header, current string) (string, error) {
	var next string
	u, _ := url.Parse(current)
	for _, line := range h.Values("Link") {
		for _, part := range strings.Split(line, ",") {
			bits := strings.Split(strings.TrimSpace(part), ";")
			if len(bits) < 2 || !strings.HasPrefix(bits[0], "<") || !strings.HasSuffix(bits[0], ">") {
				return "", ErrPagination
			}
			isNext := false
			for _, b := range bits[1:] {
				kv := strings.SplitN(strings.TrimSpace(b), "=", 2)
				if len(kv) == 2 && strings.EqualFold(kv[0], "rel") {
					for _, rel := range strings.Fields(strings.Trim(kv[1], `"`)) {
						if rel == "next" {
							isNext = true
						}
					}
				}
			}
			if !isNext {
				continue
			}
			if next != "" {
				return "", ErrPagination
			}
			v, err := url.Parse(strings.TrimSuffix(strings.TrimPrefix(bits[0], "<"), ">"))
			if err != nil || !v.IsAbs() || v.Scheme != u.Scheme || v.Host != u.Host || v.Path != u.Path || v.RawPath != u.RawPath || v.User != nil || v.Fragment != "" {
				return "", ErrPagination
			}
			next = v.String()
		}
	}
	return next, nil
}
func Segment(s string) bool {
	return s != "" && len(s) <= 255 && s != "." && s != ".." && !strings.ContainsAny(s, "/\\?%#\x00\r\n\t ")
}
