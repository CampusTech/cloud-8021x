// Package binding preserves the signed c8021x.1 accounting attribution format.
// Bindings are evidence for logs/accounting only, never authentication credentials.
package binding

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/CampusTech/cloud-8021x/internal/domain"
)

const Prefix = "c8021x.1."
const MaxAge = 30 * 24 * time.Hour
const headerSize = 8 + 12 + 32 + 2
const domainSeparator = "cloud-8021x/accounting-binding/v1\x00"

type DeviceID = domain.DeviceID
type Attribution struct {
	DeviceID    domain.DeviceID
	Fingerprint string
	VLAN        *int
	IssuedAt    time.Time
}

var macPattern = regexp.MustCompile(`^(?:[0-9a-fA-F]{12}|(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}|(?:[0-9a-fA-F]{2}-){5}[0-9a-fA-F]{2}|(?:[0-9a-fA-F]{4}\.){2}[0-9a-fA-F]{4})$`)

func contextBytes(location, station string) ([]byte, error) {
	if location == "" || len(location) > 255 || !utf8.ValidString(location) || !macPattern.MatchString(station) {
		return nil, errors.New("invalid binding context")
	}
	compact := strings.NewReplacer(":", "", "-", "", ".", "").Replace(station)
	mac, _ := hex.DecodeString(compact)
	out := append([]byte{byte(len(location))}, []byte(location)...)
	return append(out, mac...), nil
}
func ReadKey(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, errors.New("binding key unavailable")
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, 4097))
	if err != nil {
		return nil, errors.New("invalid accounting binding key")
	}
	key := bytes.Trim(data, " \t\n\r\v\f")
	if len(key) < 32 || len(key) > 4096 {
		return nil, errors.New("invalid accounting binding key")
	}
	return key, nil
}
func Issue(key []byte, identity Attribution, location, station string, now time.Time) (string, error) {
	return IssueWithRandom(key, identity, location, station, now, rand.Reader)
}
func IssueWithRandom(key []byte, identity Attribution, location, station string, now time.Time, random io.Reader) (string, error) {
	if len(key) < 32 || len(identity.DeviceID) < 1 || len(identity.DeviceID) > 96 || !utf8.ValidString(string(identity.DeviceID)) || now.Unix() < 0 || (identity.VLAN != nil && !domain.ValidVLAN(*identity.VLAN)) {
		return "", errors.New("invalid accounting binding input")
	}
	fingerprint, err := domain.NormalizeFingerprint(identity.Fingerprint)
	if err != nil {
		return "", err
	}
	ctx, err := contextBytes(location, station)
	if err != nil {
		return "", err
	}
	fp, _ := hex.DecodeString(fingerprint)
	payload := make([]byte, headerSize+len(identity.DeviceID))
	binary.BigEndian.PutUint64(payload[:8], uint64(now.Unix()))
	if _, err := io.ReadFull(random, payload[8:20]); err != nil {
		return "", errors.New("binding randomness unavailable")
	}
	copy(payload[20:52], fp)
	if identity.VLAN != nil {
		binary.BigEndian.PutUint16(payload[52:54], uint16(*identity.VLAN))
	}
	copy(payload[54:], identity.DeviceID)
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(domainSeparator))
	_, _ = mac.Write(ctx)
	_, _ = mac.Write(payload)
	token := Prefix + base64.RawURLEncoding.EncodeToString(append(payload, mac.Sum(nil)...))
	if len(token) > 253 {
		return "", errors.New("class exceeds wire bound")
	}
	return token, nil
}

// Verify returns nil for missing/duplicate/invalid attribution. Receipt is the original trusted
// native receipt timestamp, never replay/processing time. Class is intentionally not single use.
func Verify(key []byte, values []string, location string, stations []string, receipt time.Time, maxAge time.Duration) *Attribution {
	if len(key) < 32 || len(values) != 1 || len(stations) != 1 || maxAge <= 0 || maxAge > MaxAge {
		return nil
	}
	token := values[0]
	if len(token) > 508 {
		return nil
	}
	if strings.HasPrefix(token, "0x") {
		raw, err := hex.DecodeString(token[2:])
		if err != nil {
			return nil
		}
		token = string(raw)
	}
	if len(token) > 253 || !strings.HasPrefix(token, Prefix) {
		return nil
	}
	encoded := strings.TrimPrefix(token, Prefix)
	raw, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	if err != nil || base64.RawURLEncoding.EncodeToString(raw) != encoded || len(raw) < headerSize+1+32 || len(raw) > headerSize+96+32 {
		return nil
	}
	payload, sig := raw[:len(raw)-32], raw[len(raw)-32:]
	ctx, err := contextBytes(location, stations[0])
	if err != nil {
		return nil
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(domainSeparator))
	_, _ = mac.Write(ctx)
	_, _ = mac.Write(payload)
	if !hmac.Equal(sig, mac.Sum(nil)) {
		return nil
	}
	issued := binary.BigEndian.Uint64(payload[:8])
	if issued > uint64(^uint64(0)>>1) {
		return nil
	}
	issuedAt := time.Unix(int64(issued), 0)
	age := receipt.Sub(issuedAt)
	if receipt.Before(issuedAt) || age >= maxAge {
		return nil
	}
	vlan := int(binary.BigEndian.Uint16(payload[52:54]))
	if vlan != 0 && !domain.ValidVLAN(vlan) {
		return nil
	}
	device := string(payload[54:])
	if !utf8.ValidString(device) {
		return nil
	}
	out := &Attribution{DeviceID: domain.DeviceID(device), Fingerprint: hex.EncodeToString(payload[20:52]), IssuedAt: issuedAt}
	if vlan != 0 {
		out.VLAN = &vlan
	}
	return out
}

// Enrich retains signed fields even when optional inventory metadata has expired or is ambiguous.
func Enrich(verified *Attribution, s domain.Snapshot, receipt time.Time, maxAge time.Duration) *domain.DeviceMetadata {
	if verified == nil || !domain.Fresh(s.UpdatedAt, receipt, maxAge) {
		return nil
	}
	m := s.Devices[verified.DeviceID]
	if m == nil {
		return nil
	}
	copy := *m
	return &copy
}
