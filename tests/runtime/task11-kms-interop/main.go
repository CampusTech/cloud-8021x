// Development-only synthetic KMS authority seed and genuine issuance probe.
package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protowire"
)

func must(err error) {
	if err != nil {
		panic(err)
	}
}
func encoded(v any) []byte { b, err := json.MarshalIndent(v, "", "  "); must(err); return b }
func write(root, name string, data []byte) {
	p := filepath.Join(root, name)
	must(os.MkdirAll(filepath.Dir(p), 0700))
	must(os.WriteFile(p, data, 0600))
}
func pkcs8(key crypto.Signer) []byte {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	must(err)
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}
func public(key crypto.Signer) []byte {
	der, err := x509.MarshalPKIXPublicKey(key.Public())
	must(err)
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
}
func hash(data []byte) string { s := sha256.Sum256(data); return hex.EncodeToString(s[:]) }
func key() *ecdsa.PrivateKey {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	must(err)
	return k
}
func cert(name string, ca bool, k crypto.Signer, parent *x509.Certificate, signer crypto.Signer, dns []string) []byte {
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	must(err)
	now := time.Now().UTC()
	c := &x509.Certificate{SerialNumber: n, Subject: pkix.Name{CommonName: name}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(72 * time.Hour), IsCA: ca, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, DNSNames: dns}
	if ca {
		c.KeyUsage |= x509.KeyUsageCertSign | x509.KeyUsageCRLSign
		c.MaxPathLen = 1
	} else {
		c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	}
	if parent == nil {
		parent = c
		signer = k
	}
	der, err := x509.CreateCertificate(rand.Reader, c, parent, k.Public(), signer)
	must(err)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}
func certificate(data []byte) *x509.Certificate {
	p, _ := pem.Decode(data)
	if p == nil {
		panic("certificate PEM absent")
	}
	c, err := x509.ParseCertificate(p.Bytes)
	must(err)
	return c
}
func signer(data []byte) *ecdsa.PrivateKey {
	p, _ := pem.Decode(data)
	if p == nil {
		panic("key PEM absent")
	}
	k, err := x509.ParsePKCS8PrivateKey(p.Bytes)
	must(err)
	return k.(*ecdsa.PrivateKey)
}
func b64(data []byte) string { return base64.RawURLEncoding.EncodeToString(data) }
func jwk(k *ecdsa.PrivateKey) map[string]string {
	p := map[string]string{"kty": "EC", "crv": "P-256", "x": b64(k.X.FillBytes(make([]byte, 32))), "y": b64(k.Y.FillBytes(make([]byte, 32)))}
	canonical, err := json.Marshal(p)
	must(err)
	sum := sha256.Sum256(canonical)
	p["kid"] = b64(sum[:])
	return p
}

func seed(root string) {
	must(os.Mkdir(root, 0700))
	fixtureRoot := key()
	fixtureRootPEM := cert("Task11 KMS transport root", true, fixtureRoot, nil, nil, nil)
	tlsKey := key()
	tlsPEM := cert("cloudkms.googleapis.com", false, tlsKey, certificate(fixtureRootPEM), fixtureRoot, []string{"cloudkms.googleapis.com", "secretmanager.googleapis.com", "unlisted.googleapis.com"})
	write(root, "transport-root.pem", fixtureRootPEM)
	write(root, "transport-root-key.pem", pkcs8(fixtureRoot))
	kmsKeys := map[string]string{}
	identities := map[string]any{}
	for _, kind := range []string{"ec", "rsa"} {
		var rootKey, intermediateKey crypto.Signer
		if kind == "ec" {
			rootKey = key()
			intermediateKey = key()
		} else {
			r, err := rsa.GenerateKey(rand.Reader, 2048)
			must(err)
			rootKey = r
			r, err = rsa.GenerateKey(rand.Reader, 2048)
			must(err)
			intermediateKey = r
		}
		rootPEM := cert("Task11 preserved "+kind+" root", true, rootKey, nil, nil, nil)
		intermediatePEM := cert("Task11 preserved "+kind+" intermediate", true, intermediateKey, certificate(rootPEM), rootKey, nil)
		write(root, kind+"/root.pem", rootPEM)
		write(root, kind+"/intermediate.pem", intermediatePEM)
		write(root, kind+"/root-private.pem", pkcs8(rootKey))
		write(root, "private/"+kind+".pem", pkcs8(intermediateKey))
		provisioner := key()
		write(root, kind+"/provisioner.pem", pkcs8(provisioner))
		resource := "projects/111222333444/locations/us-central1/keyRings/task11/cryptoKeys/" + kind + "/cryptoKeyVersions/1"
		kmsKeys[resource] = kind + ".pem"
		config := map[string]any{"root": []string{"/work/" + kind + "/root.pem"}, "crt": "/work/" + kind + "/intermediate.pem", "key": "cloudkms:" + resource, "kms": map[string]string{"type": "cloudkms"}, "address": "127.0.0.1:8443", "dnsNames": []string{"localhost"}, "db": map[string]string{"type": "badgerv2", "dataSource": "/work/" + kind + "/db"}, "authority": map[string]any{"provisioners": []any{map[string]any{"type": "JWK", "name": "kms-interop", "key": jwk(provisioner)}}}}
		write(root, kind+"/ca.json", encoded(config))
		identities[kind] = map[string]string{"resource": resource, "root_certificate_sha256": hash(rootPEM), "intermediate_certificate_sha256": hash(intermediatePEM), "intermediate_public_sha256": hash(public(intermediateKey)), "private_key_sha256": hash(pkcs8(intermediateKey)), "root_private_sha256": hash(pkcs8(rootKey))}
	}
	fixtureSeed := encoded(map[string]any{"schema": 1, "project_id": "task11-kms-interop", "project_number": "111222333444", "secrets": map[string]any{}, "keys": kmsKeys, "routes": []any{}})
	for _, phase := range []string{"active", "passive"} {
		for _, role := range []string{"cloud", "metadata"} {
			dir := phase + "/" + role
			write(root, dir+"/seed.json", fixtureSeed)
			write(root, dir+"/tls.pem", tlsPEM)
			write(root, dir+"/tls.key", pkcs8(tlsKey))
			for _, kind := range []string{"ec", "rsa"} {
				data, err := os.ReadFile(filepath.Join(root, "private", kind+".pem"))
				must(err)
				write(root, dir+"/"+kind+".pem", data)
			}
		}
	}
	write(root, "identity.json", encoded(identities))
	fmt.Println("Generated private synthetic EC/RSA preserved roots and KMS authority inputs; only hashes recorded.")
}

func issue(root, kind string) error {
	caPath := filepath.Join(root, kind)
	rootPEM, err := os.ReadFile(filepath.Join(caPath, "root.pem"))
	if err != nil {
		return err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(rootPEM) {
		return errors.New("preserved root unavailable")
	}
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}}, Timeout: 5 * time.Second}
	defer client.CloseIdleConnections()
	for attempt := 0; attempt < 40; attempt++ {
		response, err := client.Get("https://localhost:8443/health")
		if err == nil {
			body, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
			_ = response.Body.Close()
			if response.StatusCode == 200 && bytes.Contains(body, []byte("ok")) {
				break
			}
		}
		if attempt == 39 {
			return errors.New("actual KMS authority did not become healthy")
		}
		time.Sleep(250 * time.Millisecond)
	}
	leaf := key()
	requestDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "fixture.invalid"}, DNSNames: []string{"fixture.invalid"}}, leaf)
	if err != nil {
		return err
	}
	csr := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: requestDER})
	provisionerData, err := os.ReadFile(filepath.Join(caPath, "provisioner.pem"))
	if err != nil {
		return err
	}
	provisioner := signer(provisionerData)
	now := time.Now().Unix()
	nonce := make([]byte, 16)
	if _, err = rand.Read(nonce); err != nil {
		return err
	}
	header := b64(encoded(map[string]string{"alg": "ES256", "typ": "JWT", "kid": jwk(provisioner)["kid"]}))
	claims := b64(encoded(map[string]any{"iss": "kms-interop", "sub": "fixture.invalid", "aud": "https://localhost:8443/1.0/sign", "iat": now, "nbf": now - 5, "exp": now + 120, "jti": hex.EncodeToString(nonce), "sans": []string{"fixture.invalid"}}))
	input := header + "." + claims
	digest := sha256.Sum256([]byte(input))
	r, s, err := ecdsa.Sign(rand.Reader, provisioner, digest[:])
	if err != nil {
		return err
	}
	signature := append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...)
	token := input + "." + b64(signature)
	response, err := client.Post("https://localhost:8443/1.0/sign", "application/json", bytes.NewReader(encoded(map[string]string{"csr": string(csr), "ott": token})))
	if err != nil {
		return err
	}
	defer func() { _ = response.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return err
	}
	if response.StatusCode != 201 {
		return fmt.Errorf("actual KMS issuance HTTP%d: %s", response.StatusCode, body)
	}
	var result struct {
		Cert string `json:"crt"`
		CA   string `json:"ca"`
	}
	if err = json.Unmarshal(body, &result); err != nil {
		return err
	}
	issued := certificate([]byte(result.Cert))
	intermediates := x509.NewCertPool()
	if !intermediates.AppendCertsFromPEM([]byte(result.CA)) {
		return errors.New("issued chain intermediate absent")
	}
	chains, err := issued.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, DNSName: "fixture.invalid", KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}})
	if err != nil {
		return err
	}
	if len(chains) != 1 || len(chains[0]) != 3 {
		return errors.New("issued chain did not reach exact preserved root")
	}
	originalIntermediate, err := os.ReadFile(filepath.Join(caPath, "intermediate.pem"))
	if err != nil {
		return err
	}
	if !bytes.Equal(chains[0][1].Raw, certificate(originalIntermediate).Raw) || !bytes.Equal(chains[0][2].Raw, certificate(rootPEM).Raw) {
		return errors.New("KMS issuer/root identity changed")
	}
	publicDER, err := x509.MarshalPKIXPublicKey(leaf.Public())
	if err != nil {
		return err
	}
	issuedDER, err := x509.MarshalPKIXPublicKey(issued.PublicKey)
	if err != nil {
		return err
	}
	if !bytes.Equal(publicDER, issuedDER) {
		return errors.New("issued certificate not bound to genuine CSR")
	}
	write(root, kind+"/issued.pem", []byte(result.Cert))
	write(root, kind+"/issued-chain.pem", []byte(result.Cert+result.CA+string(rootPEM)))
	write(root, kind+"/issuance-proof.json", encoded(map[string]any{"certificate_sha256": hash([]byte(result.Cert)), "preserved_root_sha256": hash(rootPEM), "preserved_intermediate_sha256": hash(originalIntermediate), "signature_algorithm": issued.SignatureAlgorithm.String(), "subject": "fixture.invalid", "chain_verified": true, "csr_key_matches": true, "chain_length": len(chains[0])}))
	fmt.Println("PASS genuine " + kind + " KMS-backed issuance, CSR binding, signature and preserved-root chain")
	return nil
}

type rawWire []byte
type rawCodec struct{}

func (rawCodec) Name() string                  { return "proto" }
func (rawCodec) Marshal(v any) ([]byte, error) { return []byte(*v.(*rawWire)), nil }
func (rawCodec) Unmarshal(data []byte, v any) error {
	*v.(*rawWire) = append((*v.(*rawWire))[:0], data...)
	return nil
}

func denials(root string) error {
	transportRoot, err := os.ReadFile(filepath.Join(root, "transport-root.pem"))
	if err != nil {
		return err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(transportRoot) {
		return errors.New("mock transport trust unavailable")
	}
	tlsConfig := &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: tlsConfig}, Timeout: 3 * time.Second}
	defer client.CloseIdleConnections()
	response, err := client.Get("http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token")
	// Metadata requires the authentic header, including for this negative probe.
	if err != nil {
		return err
	}
	_ = response.Body.Close()
	if response.StatusCode != 403 {
		return errors.New("metadata without flavor was accepted")
	}
	request, err := http.NewRequest(http.MethodGet, "http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token", nil)
	if err != nil {
		return err
	}
	request.Header.Set("Metadata-Flavor", "Google")
	response, err = client.Do(request)
	if err != nil {
		return err
	}
	var bearer struct {
		Token string `json:"access_token"`
	}
	err = json.NewDecoder(io.LimitReader(response.Body, 4096)).Decode(&bearer)
	_ = response.Body.Close()
	if err != nil || response.StatusCode != 200 || bearer.Token == "" {
		return errors.New("actual metadata token unavailable")
	}
	resource := "projects/111222333444/locations/us-central1/keyRings/task11/cryptoKeys/ec/cryptoKeyVersions/1"
	for _, item := range []struct {
		method, target string
		code           int
		auth           bool
	}{
		{http.MethodGet, "https://unlisted.googleapis.com/v1/unlisted", 404, true},
		{http.MethodPost, "https://cloudkms.googleapis.com/v1/" + resource + ":asymmetricDecrypt", 404, true},
		{http.MethodPatch, "https://cloudkms.googleapis.com/v1/" + resource + "/publicKey", 404, true},
		{http.MethodGet, "https://cloudkms.googleapis.com/v1/" + resource + "/publicKey", 401, false},
	} {
		r, err := http.NewRequest(item.method, item.target, nil)
		if err != nil {
			return err
		}
		if item.auth {
			r.Header.Set("Authorization", "Bearer "+bearer.Token)
		}
		response, err := client.Do(r)
		if err != nil {
			return err
		}
		_ = response.Body.Close()
		if response.StatusCode != item.code {
			return fmt.Errorf("unknown API/method/auth accepted HTTP%d", response.StatusCode)
		}
	}
	connection, err := grpc.NewClient("cloudkms.googleapis.com:443", grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
	if err != nil {
		return err
	}
	defer func() { _ = connection.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	ctx = metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+bearer.Token)
	requestWire := rawWire(protowire.AppendBytes(protowire.AppendTag(nil, 1, protowire.BytesType), []byte(resource)))
	var result rawWire
	err = connection.Invoke(ctx, "/google.cloud.kms.v1.KeyManagementService/Decrypt", &requestWire, &result, grpc.ForceCodec(rawCodec{}))
	if status.Code(err) != codes.PermissionDenied {
		return fmt.Errorf("unknown gRPC method was not denied: %v", err)
	}
	fmt.Println("PASS actual metadata flavor, unknown API/HTTP/gRPC methods and bearer authorization deny closed")
	return nil
}

func main() {
	if len(os.Args) != 3 && len(os.Args) != 4 {
		panic("seed ROOT or issue ROOT ec|rsa")
	}
	switch os.Args[1] {
	case "seed":
		seed(os.Args[2])
	case "issue":
		must(issue(os.Args[2], os.Args[3]))
	case "denials":
		must(denials(os.Args[2]))
	default:
		panic("unknown action")
	}
}
