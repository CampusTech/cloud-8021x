package stepca

import (
	"bytes"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

//go:embed wifi-acme.tpl
var acmeTemplate []byte

//go:embed wifi-scep.tpl
var scepTemplate []byte

type RenderOptions struct {
	ECDNS, RSADNS, ECKey, RSAKey, ECDB, RSADB, ACME, SCEP string
	WebhookPort                                           int
	Inventory                                             bool
	RSAMaterial                                           Material
}
type caConfig struct {
	Root           string             `json:"root"`
	CRT            string             `json:"crt"`
	Key            string             `json:"key"`
	KMS            map[string]string  `json:"kms"`
	Address        string             `json:"address"`
	DNSNames       []string           `json:"dnsNames"`
	MetricsAddress string             `json:"metricsAddress"`
	DB             map[string]string  `json:"db"`
	Authority      map[string]any     `json:"authority"`
	TLS            map[string]float64 `json:"tls"`
	Logger         map[string]string  `json:"logger"`
}

func Render(o RenderOptions) (map[string][]byte, error) {
	safe := regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9.-]{0,252}$`)
	for _, s := range []string{o.ECDNS, o.RSADNS, o.ACME, o.SCEP} {
		if !safe.MatchString(s) {
			return nil, errors.New("invalid CA DNS or provisioner")
		}
	}
	if o.WebhookPort < 1 || o.WebhookPort > 65535 || o.ECKey == o.RSAKey || !strings.HasPrefix(o.ECKey, "cloudkms:projects/") || !strings.HasPrefix(o.RSAKey, "cloudkms:projects/") {
		return nil, errors.New("invalid CA signer or webhook")
	}
	for i, dsn := range []string{o.ECDB, o.RSADB} {
		u, e := url.Parse(dsn)
		db := "/stepca"
		if i == 1 {
			db = "/stepca_rsa"
		}
		if e != nil || u.Scheme != "postgresql" || u.Host == "" || u.User == nil || u.User.Username() != "stepca" || u.Path != db {
			return nil, errors.New("preserved stepca database/user required")
		}
	}
	if len(o.RSAMaterial.DecrypterCert) == 0 || len(o.RSAMaterial.DecrypterKey) == 0 {
		return nil, errors.New("RSA SCEP material missing")
	}
	files := map[string][]byte{}
	for i, base := range []string{"/etc/step-ca", "/etc/step-ca-rsa"} {
		dns, key, dsn, port, metrics := o.ECDNS, o.ECKey, o.ECDB, 8443, 9090
		var provisioner map[string]any
		if i == 0 {
			provisioner = map[string]any{"type": "ACME", "name": o.ACME, "challenges": []string{"device-attest-01"}, "attestationFormats": []string{"apple"}, "options": map[string]any{"webhooks": []any{map[string]any{"name": "authorize", "url": fmt.Sprintf("https://127.0.0.1:%d/authorize", o.WebhookPort), "kind": "AUTHORIZING", "certType": "X509"}}, "x509": map[string]string{"templateFile": base + "/templates/x509/wifi-acme.tpl"}}}
			files[base+"/templates/x509/wifi-acme.tpl"] = append([]byte(nil), acmeTemplate...)
		} else {
			dns, key, dsn, port, metrics = o.RSADNS, o.RSAKey, o.RSADB, 8444, 9091
			provisioner = map[string]any{"type": "SCEP", "name": o.SCEP, "minimumPublicKeyLength": 2048, "encryptionAlgorithmIdentifier": 2, "decrypterCertificate": base64.StdEncoding.EncodeToString(o.RSAMaterial.DecrypterCert), "decrypterKeyPEM": base64.StdEncoding.EncodeToString(o.RSAMaterial.DecrypterKey), "options": map[string]any{"webhooks": []any{map[string]any{"name": "scep-challenge", "url": fmt.Sprintf("https://127.0.0.1:%d/scep-challenge", o.WebhookPort), "kind": "SCEPCHALLENGE"}}, "x509": map[string]string{"templateFile": base + "/templates/x509/wifi-scep.tpl"}}}
			// Only resolve the deployment conditional; Smallstep's own template
			// expressions remain byte-for-byte and are evaluated by its engine.
			raw := string(scepTemplate)
			a := strings.Index(raw, "{{if .Inventory}}")
			b := strings.Index(raw, "{{else}}")
			c := strings.Index(raw, "{{end}}")
			if a < 0 || b < a || c < b {
				return nil, errors.New("embedded SCEP conditional invalid")
			}
			selected := raw[b+len("{{else}}") : c]
			if o.Inventory {
				selected = raw[a+len("{{if .Inventory}}") : b]
			}
			files[base+"/templates/x509/wifi-scep.tpl"] = []byte(raw[:a] + selected + raw[c+len("{{end}}"):])
		}
		provisioner["claims"] = map[string]string{"maxTLSCertDuration": "2160h", "defaultTLSCertDuration": "2160h"}
		cfg := caConfig{Root: base + "/certs/root_ca.crt", CRT: base + "/certs/intermediate_ca.crt", Key: key, KMS: map[string]string{"type": "cloudkms"}, Address: fmt.Sprintf(":%d", port), DNSNames: []string{dns}, MetricsAddress: fmt.Sprintf("127.0.0.1:%d", metrics), DB: map[string]string{"type": "postgresql", "dataSource": dsn}, Authority: map[string]any{"provisioners": []any{provisioner}}, TLS: map[string]float64{"minVersion": 1.2, "maxVersion": 1.3}, Logger: map[string]string{"format": "json"}}
		b, e := json.MarshalIndent(cfg, "", "  ")
		if e != nil {
			return nil, errors.New("CA serialization failed")
		}
		files[base+"/config/ca.json"] = append(bytes.TrimSpace(b), '\n')
	}
	return files, nil
}
