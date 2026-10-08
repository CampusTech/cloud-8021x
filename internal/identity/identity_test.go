package identity

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func privateDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	return dir
}
func leafFile(t *testing.T, dir string, der []byte) string {
	t.Helper()
	p := filepath.Join(dir, "leaf.pem")
	if err := os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	return p
}
func TestPrivateLeafHandoffExactHashExclusiveAndSingleUse(t *testing.T) {
	dir := privateDir(t)
	h := Handoff{Directory: filepath.Join(dir, "handoff"), MaxAge: 120 * time.Second}
	path := leafFile(t, dir, []byte("verified DER"))
	token := strings.Repeat("a", 64)
	now := time.Now()
	if err := h.Record(path, token, nil, now); err != nil {
		t.Fatal(err)
	}
	d, _ := os.Stat(h.Directory)
	f, _ := os.Stat(filepath.Join(h.Directory, token))
	if d.Mode().Perm() != 0700 || f.Mode().Perm() != 0600 {
		t.Fatal("private modes")
	}
	if err := h.Record(path, token, nil, now); err == nil {
		t.Fatal("overwritten")
	}
	cert, err := h.Consume(token, f.ModTime().Add(time.Millisecond))
	digest := sha256.Sum256([]byte("verified DER"))
	if err != nil || !cert.Valid() || cert.Fingerprint() != hex.EncodeToString(digest[:]) {
		t.Fatal(cert, err)
	}
	if _, err := h.Consume(token, now.Add(time.Second)); err == nil {
		t.Fatal("replay")
	}
	for _, token := range []string{"../leaf.pem", "", strings.Repeat("X", 64)} {
		if h.Record(path, token, nil, now) == nil {
			t.Fatal("bad token")
		}
	}
}
func TestHandoffSymlinkHardlinkLockAgeAndUnlinkBeforeValidation(t *testing.T) {
	for _, kind := range []string{"symlink", "hardlink", "locked", "expired", "future", "malformed", "oversize", "publicmode"} {
		t.Run(kind, func(t *testing.T) {
			dir := privateDir(t)
			h := Handoff{Directory: dir, MaxAge: 120 * time.Second}
			token := strings.Repeat("b", 64)
			p := filepath.Join(dir, token)
			now := time.Now()
			if err := os.WriteFile(p, []byte(strings.Repeat("a1", 32)), 0600); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "symlink":
				_ = os.Remove(p)
				_ = os.Symlink("/etc/passwd", p)
			case "hardlink":
				_ = os.Link(p, filepath.Join(dir, "other"))
			case "locked":
				fd, err := os.Open(p)
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = fd.Close() }()
				if err := unix.Flock(int(fd.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
					t.Fatal(err)
				}
			case "expired":
				_ = os.Chtimes(p, now.Add(-120*time.Second), now.Add(-120*time.Second))
			case "future":
				_ = os.Chtimes(p, now.Add(time.Second), now.Add(time.Second))
			case "malformed":
				_ = os.WriteFile(p, []byte(`{"fingerprint":"bad","attested_serial":"SERIAL"}`), 0600)
			case "oversize":
				_ = os.WriteFile(p, bytes.Repeat([]byte("a"), 1025), 0600)
			case "publicmode":
				_ = os.Chmod(p, 0644)
			}
			if _, err := h.Consume(token, now); err == nil {
				t.Fatal("unsafe handoff accepted")
			}
			if kind == "expired" || kind == "future" || kind == "malformed" || kind == "oversize" {
				if _, err := os.Lstat(p); !os.IsNotExist(err) {
					t.Fatal("not consumed before validating")
				}
			}
		})
	}
}
func TestLegacyHandoffJSONAndStrictSchema(t *testing.T) {
	for _, value := range []string{strings.Repeat("AB", 32), `{"fingerprint":"` + strings.Repeat("ab", 32) + `","attested_serial":"SERIAL123"}`} {
		dir := privateDir(t)
		token := strings.Repeat("c", 64)
		_ = os.WriteFile(filepath.Join(dir, token), []byte(value), 0600)
		cert, err := (Handoff{Directory: dir, MaxAge: 120 * time.Second}).Consume(token, time.Now().Add(time.Millisecond))
		if err != nil || cert.Fingerprint() != strings.Repeat("ab", 32) {
			t.Fatal(err)
		}
	}
	for _, value := range []string{`{"fingerprint":"` + strings.Repeat("ab", 32) + `","attested_serial":"S","extra":true}`, `{"fingerprint":"` + strings.Repeat("ab", 32) + `","attested_serial":"S","attested_serial":"S"}`} {
		dir := privateDir(t)
		token := strings.Repeat("d", 64)
		_ = os.WriteFile(filepath.Join(dir, token), []byte(value), 0600)
		if _, err := (Handoff{Directory: dir, MaxAge: 120 * time.Second}).Consume(token, time.Now().Add(time.Millisecond)); err == nil {
			t.Fatal("invalid schema")
		}
	}
}
func TestStickyDowngradeGuard(t *testing.T) {
	path := filepath.Join(t.TempDir(), "guard")
	if err := CheckDowngradeGuard(path, false, false); err != nil {
		t.Fatal(err)
	}
	if err := CheckDowngradeGuard(path, true, true); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("dry run wrote guard")
	}
	if err := CheckDowngradeGuard(path, true, false); err != nil {
		t.Fatal(err)
	}
	if err := CheckDowngradeGuard(path, false, false); err == nil {
		t.Fatal("downgrade")
	}
	if err := CheckDowngradeGuard(path, true, false); err != nil {
		t.Fatal("sticky repeat", err)
	}
}

var markerOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 37476, 9000, 64, 1}
var permanentOID = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 8, 3}

func certFixture(t *testing.T, kind string) ([]byte, []byte, time.Time) {
	t.Helper()
	now := time.Now().Truncate(time.Second)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	issuer := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "WiFi CA"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	var pub any = &key.PublicKey
	var signer any = key
	if kind == "rsa" {
		r, _ := rsa.GenerateKey(rand.Reader, 2048)
		pub = &r.PublicKey
		signer = r
	}
	if kind == "issuer-expired" {
		issuer.NotAfter = now
	}
	if kind == "issuer-nonca" {
		issuer.IsCA = false
	}
	issuerDER, err := x509.CreateCertificate(rand.Reader, issuer, issuer, pub, signer)
	if err != nil {
		t.Fatal(err)
	}
	issuerParsed, err := x509.ParseCertificate(issuerDER)
	if err != nil {
		t.Fatal(err)
	}
	serial := "SERIAL123"
	if kind == "bad-cn" {
		serial = "SERIAL-123"
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: serial}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Minute), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, BasicConstraintsValid: true}
	if kind == "expired" {
		leaf.NotAfter = now
	}
	if kind == "future" {
		leaf.NotBefore = now.Add(time.Second)
	}
	if kind == "ca" {
		leaf.IsCA = true
	}
	if kind == "serverauth" {
		leaf.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	}
	provisioner := []byte("wifi-acme")
	typeID := byte(6)
	if kind == "wrong-provisioner" {
		provisioner = []byte("other-acme")
	}
	if kind == "scep" {
		typeID = 8
	}
	marker := append([]byte{2, 1, typeID, 4, byte(len(provisioner))}, provisioner...)
	marker = append(marker, 4, 0)
	marker = append([]byte{48, byte(len(marker))}, marker...)
	sanSerial := serial
	if kind == "wrong-id" {
		sanSerial = "OTHER123"
	}
	id := append([]byte{48, byte(len(sanSerial) + 2), 12, byte(len(sanSerial))}, []byte(sanSerial)...)
	oid, _ := asn1.Marshal(permanentOID)
	otherName := append(oid, append([]byte{160, byte(len(id))}, id...)...)
	otherName = append([]byte{160, byte(len(otherName))}, otherName...)
	if kind == "duplicate-id" {
		otherName = append(otherName, otherName...)
	}
	san := append([]byte{48, byte(len(otherName))}, otherName...)
	leaf.ExtraExtensions = []pkix.Extension{{Id: markerOID, Value: marker}, {Id: asn1.ObjectIdentifier{2, 5, 29, 17}, Value: san}}
	if kind == "missing-marker" {
		leaf.ExtraExtensions = leaf.ExtraExtensions[1:]
	}
	if kind == "bad-signature" {
		signer, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		issuerParsed.PublicKey = &signer.(*ecdsa.PrivateKey).PublicKey
	}
	if kind == "duplicate-cn" {
		leaf.Subject.ExtraNames = []pkix.AttributeTypeAndValue{{Type: asn1.ObjectIdentifier{2, 5, 4, 3}, Value: serial}, {Type: asn1.ObjectIdentifier{2, 5, 4, 3}, Value: serial}}
	}
	der, err := x509.CreateCertificate(rand.Reader, leaf, issuerParsed, pub, signer)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: issuerDER}), now
}
func TestAttestedACMEPinnedIssuerAndExactExtensions(t *testing.T) {
	for _, kind := range []string{"valid", "rsa", "issuer-expired", "issuer-nonca", "bad-cn", "expired", "future", "ca", "serverauth", "wrong-provisioner", "scep", "wrong-id", "duplicate-id", "missing-marker", "bad-signature", "duplicate-cn"} {
		t.Run(kind, func(t *testing.T) {
			leaf, issuer, now := certFixture(t, kind)
			s := RecognizeAttested(leaf, issuer, "wifi-acme", now)
			if kind == "valid" {
				if s != "SERIAL123" {
					t.Fatal("valid rejected")
				}
				dir := privateDir(t)
				h := Handoff{Directory: filepath.Join(dir, "handoff"), MaxAge: 120 * time.Second}
				path := filepath.Join(dir, "leaf")
				_ = os.WriteFile(path, leaf, 0600)
				token := strings.Repeat("e", 64)
				if err := h.Record(path, token, &Attestation{IssuerPEM: issuer, Provisioner: "wifi-acme"}, now); err != nil {
					t.Fatal(err)
				}
				raw, _ := os.ReadFile(filepath.Join(h.Directory, token))
				var body map[string]string
				if json.Unmarshal(raw, &body) != nil || body["attested_serial"] != "SERIAL123" {
					t.Fatal("handoff attestation")
				}
			} else if s != "" {
				t.Fatal("invalid attestation recognized", kind)
			}
			if kind == "scep" {
				dir := privateDir(t)
				h := Handoff{Directory: dir, MaxAge: 120 * time.Second}
				if err := h.Record(leafFile(t, t.TempDir(), mustDER(t, leaf)), strings.Repeat("f", 64), &Attestation{IssuerPEM: issuer, Provisioner: "wifi-acme"}, now); err != nil {
					t.Fatal(err)
				}
				cert, err := h.Consume(strings.Repeat("f", 64), time.Now().Add(time.Millisecond))
				if err != nil || cert.AttestedSerial() != "" {
					t.Fatal("invalid recognition did not fall back fingerprint")
				}
			}
		})
	}
}
func mustDER(t *testing.T, p []byte) []byte {
	t.Helper()
	b, _ := pem.Decode(p)
	if b == nil {
		t.Fatal("PEM")
	}
	return b.Bytes
}
func TestRecordPEMHashesTheAlreadyReadLeafWithoutReopeningInput(t *testing.T) {
	dir := privateDir(t)
	h := Handoff{Directory: dir, MaxAge: 120 * time.Second}
	leaf := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("already parsed leaf")})
	token := strings.Repeat("a", 64)
	if err := h.RecordPEM(leaf, token, nil, time.Now()); err != nil {
		t.Fatal(err)
	}
	cert, err := h.Consume(token, time.Now())
	sum := sha256.Sum256([]byte("already parsed leaf"))
	if err != nil || cert.Fingerprint() != hex.EncodeToString(sum[:]) {
		t.Fatal("verified/recorded bytes diverged", err)
	}
}
