// Package auth imports only the separate native final-auth detail stream.
// Accounting detail files belong exclusively to FreeRADIUS's native reader.
package auth

import (
	"bytes"
	"errors"
	"strconv"
	"strings"
	"unicode/utf8"
)

const MaxRecord = 65536

type Record struct{ Values map[string][]string }

var allowed = map[string]bool{
	// Harmless native legacy-cache descriptors are tolerated for retained files;
	// current templates suppress these and the event projection never exports them.
	"TLS-Client-Cert-Valid-Since": true, "TLS-Client-Cert-X509v3-Extended-Key-Usage-OID": true,
	"Packet-Type": true, "Timestamp": true, "Response-Packet-Type": true,
	"C8021X-Receipt": true, "C8021X-Client": true, "C8021X-Location": true, "C8021X-Source": true,
	"C8021X-Station": true, "C8021X-Called": true, "C8021X-Port-Type": true, "C8021X-Reason": true,
	"C8021X-Port-Count": true, "C8021X-Station-Count": true,
	"Class": true, "Tunnel-Type": true, "Tunnel-Medium-Type": true, "Tunnel-Private-Group-Id": true,
}

// Parse accepts FreeRADIUS's escaped detail grammar, never JSON interpolation.
// Zero consumed means an incomplete tail; malformed complete records stop import.
func Parse(data []byte) (Record, int, error) {
	r := Record{Values: map[string][]string{}}
	end := bytes.Index(data, []byte("\n\n"))
	if end < 0 {
		if len(data) > MaxRecord {
			return r, 0, errors.New("auth record exceeds limit")
		}
		return r, 0, nil
	}
	end += 2
	if end > MaxRecord || !utf8.Valid(data[:end]) {
		return r, 0, errors.New("invalid auth record encoding or size")
	}
	lines := strings.Split(string(data[:end-2]), "\n")
	if len(lines) < 2 || len(lines[0]) > 128 {
		return r, 0, errors.New("invalid auth detail header")
	}
	for _, line := range lines[1:] {
		if !strings.HasPrefix(line, "\t") {
			return r, 0, errors.New("invalid auth detail line")
		}
		key, value, ok := strings.Cut(strings.TrimPrefix(line, "\t"), " = ")
		if !ok || !allowed[key] || len(r.Values[key]) >= 200 {
			return r, 0, errors.New("unexpected auth detail attribute")
		}
		decoded, err := decode(value)
		if err != nil {
			return r, 0, err
		}
		r.Values[key] = append(r.Values[key], decoded)
	}
	if values := r.Values["Packet-Type"]; len(values) != 1 || (values[0] != "Access-Accept" && values[0] != "Access-Reject") {
		return r, 0, errors.New("not a final auth outcome")
	}
	return r, end, nil
}
func decode(s string) (string, error) {
	if len(s) > 4096 {
		return "", errors.New("auth value exceeds limit")
	}
	if !strings.HasPrefix(s, "\"") {
		if strings.ContainsAny(s, "\"\r\n\\\x00") {
			return "", errors.New("invalid auth scalar")
		}
		return s, nil
	}
	if len(s) < 2 || s[len(s)-1] != '"' {
		return "", errors.New("unterminated auth value")
	}
	s = s[1 : len(s)-1]
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '"' || c < 32 {
			return "", errors.New("unescaped auth value")
		}
		if c != '\\' {
			b.WriteByte(c)
			continue
		}
		i++
		if i >= len(s) {
			return "", errors.New("invalid auth escape")
		}
		switch s[i] {
		case '\\', '"':
			b.WriteByte(s[i])
		case 'n':
			b.WriteByte('\n')
		case 'r':
			b.WriteByte('\r')
		case 't':
			b.WriteByte('\t')
		default:
			if i+2 >= len(s) || s[i] < '0' || s[i] > '7' {
				return "", errors.New("invalid auth escape")
			}
			n, e := strconv.ParseUint(s[i:i+3], 8, 8)
			if e != nil {
				return "", errors.New("invalid auth octal escape")
			}
			b.WriteByte(byte(n))
			i += 2
		}
	}
	if !utf8.ValidString(b.String()) || strings.ContainsRune(b.String(), 0) {
		return "", errors.New("invalid decoded auth value")
	}
	return b.String(), nil
}
