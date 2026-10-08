package fleet

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"testing"
	"time"

	"howett.net/plist"
)

func certFixture(t *testing.T) ([]byte, []byte) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	now := time.Now()
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test CA"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(48 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	parsed, _ := x509.ParseCertificate(der)
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "irrelevant"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	public, err := x509.CreateCertificate(rand.Reader, leaf, parsed, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), public
}
func TestAppleExactManagedResultProvenance(t *testing.T) {
	ca, der := certFixture(t)
	trust, err := NewTrust(ca)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	at := now.Truncate(time.Second).Format(time.RFC3339)
	command := reservation{UUID: "command", HostID: 1, HostUUID: "host", EnrolledAt: float64(now.Add(-time.Hour).Unix()), CreatedAt: float64(now.Add(-time.Minute).Unix()), Transport: "apple", ManagedOnly: true}
	plist := fmt.Sprintf(`<?xml version="1.0"?><plist version="1.0"><dict><key>CommandUUID</key><string>command</string><key>UDID</key><string>host</string><key>Status</key><string>Acknowledged</string><key>CertificateList</key><array><dict><key>IsIdentity</key><true/><key>IsManaged</key><true/><key>Data</key><data>%s</data></dict></array></dict></plist>`, base64.StdEncoding.EncodeToString(der))
	row := appleResult{HostUUID: "host", CommandUUID: "command", RequestType: "CertificateList", Status: "Acknowledged", UpdatedAt: at, Result: base64.StdEncoding.EncodeToString([]byte(plist))}
	ob, err := appleObservation(row, command, trust, now, 24*time.Hour)
	if err != nil || len(ob.Fingerprints) != 1 || !ob.TrustVerified {
		t.Fatalf("valid %+v %v", ob, err)
	}
	for _, mutate := range []func(*appleResult){func(r *appleResult) { r.HostUUID = "wrong" }, func(r *appleResult) { r.CommandUUID = "wrong" }, func(r *appleResult) {
		r.Result = base64.StdEncoding.EncodeToString([]byte(`<plist><dict><key>CommandUUID</key><string>command</string><key>CommandUUID</key><string>command</string></dict></plist>`))
	}, func(r *appleResult) { r.UpdatedAt = now.Add(time.Hour).Format(time.RFC3339) }} {
		bad := row
		mutate(&bad)
		if _, err := appleObservation(bad, command, trust, now, 24*time.Hour); err == nil {
			t.Fatal("invalid authenticated provenance accepted")
		}
	}
}
func TestWindowsNonceScriptHostAndObservationBinding(t *testing.T) {
	ca, der := certFixture(t)
	trust, _ := NewTrust(ca)
	now := time.Now()
	command := reservation{UUID: "nonce", ExecutionID: "execution", HostID: 7, HostUUID: "host", EnrolledAt: float64(now.Add(-time.Hour).Unix()), CreatedAt: float64(now.Add(-time.Minute).Unix()), Transport: "windows", Script: "SYSTEM fixture\n# Collection nonce: nonce\n"}
	data, _ := json.Marshal(map[string]any{"version": 1, "certificates": []string{base64.StdEncoding.EncodeToString(der)}})
	zero := 0
	row := windowsResult{HostID: 7, ExecutionID: "execution", Script: command.Script, ExitCode: &zero, CreatedAt: now.Add(-30 * time.Second).Format(time.RFC3339), Output: string(data)}
	ob, err := windowsObservation(row, command, trust, now, 24*time.Hour)
	if err != nil || len(ob.Fingerprints) != 1 {
		t.Fatalf("valid Windows %v", err)
	}
	for _, mutate := range []func(*windowsResult){func(r *windowsResult) { r.HostID = 8 }, func(r *windowsResult) { r.ExecutionID = "other" }, func(r *windowsResult) { r.Script = "other nonce" }, func(r *windowsResult) { r.Output = `{"version":1,"version":1,"certificates":[]}` }, func(r *windowsResult) { r.Output = `{"version":1,"certificates":["broken"]}` }} {
		bad := row
		mutate(&bad)
		if _, err := windowsObservation(bad, command, trust, now, 24*time.Hour); err == nil {
			t.Fatal("unbound Windows result accepted")
		}
	}
}

func TestAppleBinaryAndManagedOnlyProvenance(t *testing.T) {
	ca, der := certFixture(t)
	trust, _ := NewTrust(ca)
	now := time.Now()
	r := reservation{UUID: "command", HostID: 1, HostUUID: "host", EnrolledAt: float64(now.Add(-time.Hour).Unix()), CreatedAt: float64(now.Add(-time.Minute).Unix()), Transport: "apple", ManagedOnly: true}
	data, err := plist.Marshal(map[string]any{"CommandUUID": "command", "UDID": "host", "Status": "Acknowledged", "CertificateList": []any{map[string]any{"IsIdentity": true, "Data": der}}}, plist.BinaryFormat)
	if err != nil {
		t.Fatal(err)
	}
	row := appleResult{HostUUID: "host", CommandUUID: "command", RequestType: "CertificateList", Status: "Acknowledged", UpdatedAt: now.Truncate(time.Second).Format(time.RFC3339), Result: base64.StdEncoding.EncodeToString(data)}
	if ob, err := appleObservation(row, r, trust, now, 24*time.Hour); err != nil || len(ob.Fingerprints) != 1 {
		t.Fatalf("real Apple schema binary %v", err)
	}
	r.ManagedOnly = false
	if _, err := appleObservation(row, r, trust, now, 24*time.Hour); err == nil {
		t.Fatal("missing durable ManagedOnly proof accepted")
	}
	duplicate, _ := plist.Marshal(map[string]any{"A": "one", "B": "two"}, plist.BinaryFormat)
	duplicate = bytes.Replace(duplicate, []byte{0x51, 'B'}, []byte{0x51, 'A'}, 1)
	if _, err := decodePlist(duplicate); err == nil {
		t.Fatal("binary duplicate dictionary keys accepted")
	}
	for _, data := range [][]byte{[]byte("bplist00"), append([]byte("bplist00"), make([]byte, 40)...)} {
		if _, err := decodePlist(data); err == nil {
			t.Fatal("invalid binary bounds accepted")
		}
	}
}

func TestAppleRejectsNestedScalarAndDuplicateDER(t *testing.T) {
	ca, der := certFixture(t)
	trust, _ := NewTrust(ca)
	now := time.Now()
	r := reservation{UUID: "command", HostID: 1, HostUUID: "host", EnrolledAt: float64(now.Add(-time.Hour).Unix()), CreatedAt: float64(now.Add(-time.Minute).Unix()), Transport: "apple", ManagedOnly: true}
	entry := `<dict><key>IsIdentity</key><true/><key>Data</key><data>` + base64.StdEncoding.EncodeToString(der) + `</data></dict>`
	for _, contents := range []string{`<key>CommandUUID</key><string>command<dict/></string><key>UDID</key><string>host</string><key>Status</key><string>Acknowledged</string><key>CertificateList</key><array>` + entry + `</array>`, `<key>CommandUUID</key><string>command</string><key>UDID</key><string>host</string><key>Status</key><string>Acknowledged</string><key>CertificateList</key><array>` + entry + entry + `</array>`} {
		row := appleResult{HostUUID: "host", CommandUUID: "command", RequestType: "CertificateList", Status: "Acknowledged", UpdatedAt: now.Truncate(time.Second).Format(time.RFC3339), Result: base64.StdEncoding.EncodeToString([]byte(`<plist><dict>` + contents + `</dict></plist>`))}
		if _, err := appleObservation(row, r, trust, now, time.Hour); err == nil {
			t.Fatal("malformed scalar or duplicate DER accepted")
		}
	}
}

func TestPinnedTrustRejectsWrongCAValidityPurposeAndAcceptsRSA(t *testing.T) {
	ecBundle, ecDER := certFixture(t)
	ecTrust, _ := NewTrust(ecBundle)
	wrongBundle, _ := certFixture(t)
	wrongTrust, _ := NewTrust(wrongBundle)
	now := time.Now()
	if _, _, err := wrongTrust.verify(ecDER, now); err == nil {
		t.Fatal("wrong pinned CA accepted")
	}
	if _, _, err := ecTrust.verify(ecDER, now.Add(25*time.Hour)); err == nil {
		t.Fatal("expired client identity accepted")
	}
	if _, _, err := ecTrust.verify(ecDER, now.Add(-2*time.Hour)); err == nil {
		t.Fatal("not-yet-valid client identity accepted")
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(10), Subject: pkix.Name{CommonName: "RSA fixture CA"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(48 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &rsaKey.PublicKey, rsaKey)
	if err != nil {
		t.Fatal(err)
	}
	root, _ := x509.ParseCertificate(caDER)
	bundle := append(ecBundle, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})...)
	trust, err := NewTrust(bundle)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(11), Subject: pkix.Name{CommonName: "not identity"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, leaf, root, &rsaKey.PublicKey, rsaKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = trust.verify(der, now); err != nil {
		t.Fatal("RSA SCEP bundle not accepted", err)
	}
	leaf.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	serverDER, err := x509.CreateCertificate(rand.Reader, leaf, root, &rsaKey.PublicKey, rsaKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = trust.verify(serverDER, now); err == nil {
		t.Fatal("wrong certificate purpose accepted")
	}
	if _, err = NewTrust(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})); err == nil {
		t.Fatal("caller leaf injected as trust root")
	}
}
