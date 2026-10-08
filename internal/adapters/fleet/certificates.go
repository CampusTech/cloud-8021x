package fleet

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"encoding/xml"
	"errors"
	"io"
	"math"
	"sort"
	"strings"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/domain"
)

type Trust struct {
	pool   *x509.CertPool
	digest string
}

func NewTrust(bundle []byte) (*Trust, error) {
	if len(bundle) == 0 || len(bundle) > 1<<20 {
		return nil, errors.New("invalid certificate trust bundle")
	}
	pool := x509.NewCertPool()
	remaining := bundle
	count := 0
	for len(bytes.TrimSpace(remaining)) > 0 {
		block, rest := pem.Decode(remaining)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return nil, errors.New("invalid certificate trust bundle")
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil || !cert.IsCA || !cert.BasicConstraintsValid || cert.KeyUsage&x509.KeyUsageCertSign == 0 {
			return nil, errors.New("certificate trust requires CA certificates")
		}
		pool.AddCert(cert)
		remaining = rest
		count++
	}
	if count == 0 {
		return nil, errors.New("empty certificate trust bundle")
	}
	digest := sha256.Sum256(bundle)
	return &Trust{pool: pool, digest: hex.EncodeToString(digest[:])}, nil
}
func (t *Trust) verify(der []byte, now time.Time) (string, domain.Timestamp, error) {
	if t == nil || t.pool == nil || len(der) == 0 || len(der) > 64<<10 {
		return "", 0, errors.New("missing certificate trust or invalid DER")
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil || cert.IsCA || !bytes.Equal(cert.Raw, der) {
		return "", 0, errors.New("invalid exact client certificate DER")
	}
	// Verify's ANY-EKU behavior for leaves without EKU is unsuitable here: require
	// explicit clientAuth in addition to validating the pinned full chain/purpose.
	clientAuth := false
	for _, usage := range cert.ExtKeyUsage {
		if usage == x509.ExtKeyUsageClientAuth {
			clientAuth = true
		}
	}
	if !clientAuth {
		return "", 0, errors.New("certificate is not a client identity")
	}
	if _, err = cert.Verify(x509.VerifyOptions{Roots: t.pool, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		return "", 0, errors.New("certificate failed pinned trust validation")
	}
	digest := sha256.Sum256(der)
	return hex.EncodeToString(digest[:]), domain.Unix(cert.NotAfter), nil
}

type reservation struct {
	ManagedOnly     bool    `json:"managed_only"`
	Key             string  `json:"collection_key"`
	LegacyScope     string  `json:"legacy_scope,omitempty"`
	UUID            string  `json:"command_uuid"`
	HostID          int     `json:"host_id"`
	HostUUID        string  `json:"host_uuid"`
	EnrolledAt      float64 `json:"enrolled_at"`
	FleetEnrolledAt string  `json:"fleet_enrolled_at"`
	CreatedAt       float64 `json:"created_at"`
	Transport       string  `json:"transport"`
	ExecutionID     string  `json:"execution_id,omitempty"`
	Script          string  `json:"script,omitempty"`
	Trust           string  `json:"trust"`
}
type appleResult struct {
	HostUUID    string `json:"host_uuid"`
	CommandUUID string `json:"command_uuid"`
	RequestType string `json:"request_type"`
	Status      string `json:"status"`
	UpdatedAt   string `json:"updated_at"`
	Result      string `json:"result"`
}
type windowsResult struct {
	HostID      int    `json:"host_id"`
	ExecutionID string `json:"execution_id"`
	Script      string `json:"script_contents"`
	ExitCode    *int   `json:"exit_code"`
	CreatedAt   string `json:"created_at"`
	Output      string `json:"output"`
}

func observed(raw string, r reservation, now time.Time, maxAge time.Duration) (domain.Timestamp, error) {
	at, err := time.Parse(time.RFC3339Nano, raw)
	stamp := domain.Unix(at)
	if err != nil || maxAge <= 0 || float64(stamp) < math.Max(math.Floor(r.CreatedAt), r.EnrolledAt) || !domain.Fresh(stamp, now, maxAge) {
		return 0, errors.New("certificate observation outside command, enrollment or freshness window")
	}
	return stamp, nil
}
func observation(r reservation, at domain.Timestamp, trust *Trust, ders [][]byte, now time.Time) (domain.CertificateObservation, error) {
	if trust == nil {
		return domain.CertificateObservation{}, errors.New("certificate collection requires pinned trust")
	}
	out := domain.CertificateObservation{DeviceID: domain.DeviceID("fleet:" + itoa(r.HostID)), ObservedAt: at, TrustVerified: true, Provenance: r.Transport + ":" + r.UUID + ":" + r.HostUUID, ExpiresAt: map[string]domain.Timestamp{}, Fingerprints: []string{}}
	seen := map[string]bool{}
	for _, der := range ders {
		rawHash := sha256.Sum256(der)
		rawFP := hex.EncodeToString(rawHash[:])
		if seen[rawFP] {
			return domain.CertificateObservation{}, errors.New("duplicate certificate result")
		}
		seen[rawFP] = true
		fp, expiry, err := trust.verify(der, now)
		if err != nil {
			// A well-formed unrelated identity is outside this CA's scope; malformed DER
			// is a partial collection, never an authenticated empty observation.
			if _, parseErr := x509.ParseCertificate(der); parseErr != nil {
				return domain.CertificateObservation{}, errors.New("malformed collected DER")
			}
			continue
		}
		out.Fingerprints = append(out.Fingerprints, fp)
		out.ExpiresAt[fp] = expiry
	}
	sort.Strings(out.Fingerprints)
	return out, nil
}
func appleObservation(row appleResult, r reservation, trust *Trust, now time.Time, maxAge time.Duration) (domain.CertificateObservation, error) {
	if !r.ManagedOnly || row.HostUUID != r.HostUUID || row.CommandUUID != r.UUID || row.RequestType != "CertificateList" || row.Status != "Acknowledged" {
		return domain.CertificateObservation{}, errors.New("apple result does not match reserved host command")
	}
	at, err := observed(row.UpdatedAt, r, now, maxAge)
	if err != nil {
		return domain.CertificateObservation{}, err
	}
	data, err := base64.StdEncoding.Strict().DecodeString(row.Result)
	if err != nil || len(data) > MaxResponseBytes {
		return domain.CertificateObservation{}, errors.New("invalid Apple result encoding")
	}
	payload, err := decodePlist(data)
	if err != nil {
		return domain.CertificateObservation{}, err
	}
	m, ok := payload.(map[string]any)
	if !ok || m["CommandUUID"] != r.UUID || m["Status"] != "Acknowledged" {
		return domain.CertificateObservation{}, errors.New("apple plist command/status mismatch")
	}
	matched := false
	for _, key := range []string{"UDID", "EnrollmentID"} {
		v := m[key]
		if v == r.HostUUID {
			matched = true
		}
		if v != nil && v != "" && v != r.HostUUID {
			return domain.CertificateObservation{}, errors.New("apple plist host mismatch")
		}
	}
	certs, ok := m["CertificateList"].([]any)
	if !matched || !ok || len(certs) > 256 {
		return domain.CertificateObservation{}, errors.New("apple certificate list missing or oversized")
	}
	ders := [][]byte{}
	for _, entry := range certs {
		cert, ok := entry.(map[string]any)
		if !ok {
			return domain.CertificateObservation{}, errors.New("malformed Apple certificate entry")
		}
		if cert["IsIdentity"] != true {
			continue
		}
		der, ok := cert["Data"].([]byte)
		if !ok || len(der) == 0 {
			return domain.CertificateObservation{}, errors.New("managed Apple identity lacks DER")
		}
		ders = append(ders, der)
	}
	return observation(r, at, trust, ders, now)
}
func windowsObservation(row windowsResult, r reservation, trust *Trust, now time.Time, maxAge time.Duration) (domain.CertificateObservation, error) {
	if row.HostID != r.HostID || row.ExecutionID != r.ExecutionID || row.Script != r.Script || row.ExitCode == nil || *row.ExitCode != 0 || len(row.Output) > 9002 {
		return domain.CertificateObservation{}, errors.New("windows result does not match reserved host, execution or nonce")
	}
	at, err := observed(row.CreatedAt, r, now, maxAge)
	if err != nil {
		return domain.CertificateObservation{}, err
	}
	var payload struct {
		Version      int       `json:"version"`
		Certificates *[]string `json:"certificates"`
	}
	if domain.DecodeJSONStrict([]byte(row.Output), &payload) != nil || payload.Version != 1 || payload.Certificates == nil {
		return domain.CertificateObservation{}, errors.New("invalid Windows machine certificate inventory")
	}
	ders := [][]byte{}
	for _, encoded := range *payload.Certificates {
		der, err := base64.StdEncoding.Strict().DecodeString(encoded)
		if err != nil || len(der) == 0 {
			return domain.CertificateObservation{}, errors.New("invalid Windows public DER encoding")
		}
		ders = append(ders, der)
	}
	return observation(r, at, trust, ders, now)
}

// XML uses a strict duplicate-aware parser; binary decoding is prevalidated.
func decodePlist(data []byte) (any, error) {
	if bytes.HasPrefix(data, []byte("bplist")) {
		return decodeBinaryPlist(data)
	}
	dec := xml.NewDecoder(bytes.NewReader(data))
	var parse func(xml.StartElement, int) (any, error)
	next := func() (xml.Token, error) {
		for {
			token, err := dec.Token()
			if err != nil {
				return nil, err
			}
			if text, ok := token.(xml.CharData); ok && strings.TrimSpace(string(text)) == "" {
				continue
			}
			if _, ok := token.(xml.ProcInst); ok {
				continue
			}
			if _, ok := token.(xml.Directive); ok {
				continue
			}
			return token, nil
		}
	}
	parse = func(start xml.StartElement, depth int) (any, error) {
		if depth > 16 || start.Name.Space != "" {
			return nil, errors.New("invalid plist nesting")
		}
		switch start.Name.Local {
		case "plist":
			token, err := next()
			if err != nil {
				return nil, err
			}
			child, ok := token.(xml.StartElement)
			if !ok {
				return nil, errors.New("missing plist value")
			}
			value, err := parse(child, depth+1)
			if err != nil {
				return nil, err
			}
			token, err = next()
			end, ok := token.(xml.EndElement)
			if err != nil || !ok || end.Name != start.Name {
				return nil, errors.New("invalid plist container")
			}
			return value, nil
		case "dict":
			m := map[string]any{}
			for {
				token, err := next()
				if err != nil {
					return nil, err
				}
				if end, ok := token.(xml.EndElement); ok && end.Name == start.Name {
					return m, nil
				}
				keyStart, ok := token.(xml.StartElement)
				if !ok || keyStart.Name.Local != "key" {
					return nil, errors.New("invalid plist dictionary")
				}
				var key string
				key, err = readXMLScalar(dec, keyStart)
				if err != nil {
					return nil, err
				}
				if _, ok = m[key]; ok {
					return nil, errors.New("duplicate plist field")
				}
				token, err = next()
				if err != nil {
					return nil, err
				}
				valueStart, ok := token.(xml.StartElement)
				if !ok {
					return nil, errors.New("missing plist dictionary value")
				}
				value, err := parse(valueStart, depth+1)
				if err != nil {
					return nil, err
				}
				m[key] = value
				if len(m) > 1024 {
					return nil, errors.New("oversized plist dictionary")
				}
			}
		case "array":
			a := []any{}
			for {
				token, err := next()
				if err != nil {
					return nil, err
				}
				if end, ok := token.(xml.EndElement); ok && end.Name == start.Name {
					return a, nil
				}
				child, ok := token.(xml.StartElement)
				if !ok {
					return nil, errors.New("invalid plist array")
				}
				value, err := parse(child, depth+1)
				if err != nil {
					return nil, err
				}
				a = append(a, value)
				if len(a) > 1024 {
					return nil, errors.New("oversized plist array")
				}
			}
		case "string", "integer", "data", "date", "true", "false":
			var value string
			value, err := readXMLScalar(dec, start)
			if err != nil {
				return nil, err
			}
			switch start.Name.Local {
			case "data":
				compact := strings.Join(strings.Fields(value), "")
				der, err := base64.StdEncoding.Strict().DecodeString(compact)
				if err != nil {
					return nil, errors.New("invalid plist data")
				}
				return der, nil
			case "true":
				if strings.TrimSpace(value) != "" {
					return nil, errors.New("invalid plist boolean")
				}
				return true, nil
			case "false":
				if strings.TrimSpace(value) != "" {
					return nil, errors.New("invalid plist boolean")
				}
				return false, nil
			default:
				return value, nil
			}
		default:
			return nil, errors.New("unsupported plist type")
		}
	}
	token, err := next()
	if err != nil {
		return nil, errors.New("invalid XML plist")
	}
	start, ok := token.(xml.StartElement)
	if !ok || start.Name.Local != "plist" {
		return nil, errors.New("invalid XML plist")
	}
	value, err := parse(start, 0)
	if err != nil {
		return nil, errors.New("invalid or duplicate XML plist")
	}
	if _, err = next(); !errors.Is(err, io.EOF) {
		return nil, errors.New("trailing plist data")
	}
	return value, nil
}

func readXMLScalar(dec *xml.Decoder, start xml.StartElement) (string, error) {
	if start.Name.Space != "" {
		return "", errors.New("invalid plist scalar namespace")
	}
	var value strings.Builder
	for {
		token, err := dec.Token()
		if err != nil {
			return "", err
		}
		switch t := token.(type) {
		case xml.CharData:
			if value.Len()+len(t) > 1<<20 {
				return "", errors.New("oversized plist scalar")
			}
			value.Write(t)
		case xml.EndElement:
			if t.Name != start.Name {
				return "", errors.New("invalid plist scalar ending")
			}
			return value.String(), nil
		default:
			return "", errors.New("nested or malformed plist scalar")
		}
	}
}
