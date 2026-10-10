package main

import (
	"bytes"
	"crypto/x509"
	"errors"
	"net/http"
	"slices"

	"github.com/CampusTech/cloud-8021x/internal/domain"
	"github.com/CampusTech/cloud-8021x/internal/migration"
)

const rejectedDevice = "22222222-3333-4444-8555-666666666666"

func fixedRejectNASConfig() []byte {
	return bytes.ReplaceAll(bytes.ReplaceAll(fixedNASConfig(), []byte("/client.pem"), []byte("/reject-client.pem")), []byte("/client.key"), []byte("/reject-client.key"))
}
func validateRejectClient(ec ecClientPlan, m map[string][]byte, pins map[string]string) (*x509.Certificate, error) {
	if len(pins) != 3 || !bytes.Equal(m["reject-eap.conf"], fixedRejectNASConfig()) {
		return nil, errors.New("fixed independently pinned rejection profile required")
	}
	for _, n := range nasRejectMaterialNames {
		if !shaPattern.MatchString(pins[n]) || len(m[n]) == 0 || digestBytes(m[n]) != pins[n] {
			return nil, errors.New("rejection material differs")
		}
	}
	ec.ClientCertificateSHA256 = pins["reject-client.pem"]
	ec.ClientKeySHA256 = pins["reject-client.key"]
	c, e := pinnedECClient(ec, m["ec-root.pem"], m["ec-intermediate.pem"], m["reject-client.pem"], m["reject-client.key"])
	if e != nil {
		return nil, e
	}
	defer c.CloseIdleConnections()
	transport, ok := c.Transport.(*http.Transport)
	if !ok || transport.TLSClientConfig == nil || len(transport.TLSClientConfig.Certificates) != 1 || len(transport.TLSClientConfig.Certificates[0].Certificate) != 2 {
		return nil, errors.New("trusted rejection client chain unavailable")
	}
	leaf, e := x509.ParseCertificate(transport.TLSClientConfig.Certificates[0].Certificate[0])
	if e != nil || leaf.Subject.CommonName != rejectedDevice || leaf.IsCA || leaf.KeyUsage != x509.KeyUsageDigitalSignature || len(leaf.ExtKeyUsage) != 1 || leaf.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth || len(leaf.UnknownExtKeyUsage)+len(leaf.DNSNames)+len(leaf.IPAddresses)+len(leaf.EmailAddresses)+len(leaf.URIs) != 0 || bytes.Equal(m["client.pem"], m["reject-client.pem"]) || bytes.Equal(m["client.key"], m["reject-client.key"]) {
		return nil, errors.New("independent client-only rejection identity required")
	}
	return leaf, nil
}
func rejectClientAbsent(leaf *x509.Certificate, policy domain.Snapshot, rawState []byte) error {
	fp := digestBytes(leaf.Raw)
	for _, records := range []map[string]*domain.DeviceRecord{policy.Identities, policy.Certificates, policy.HardwareSerials} {
		if records[rejectedDevice] != nil || records[fp] != nil {
			return errors.New("rejection client already present in original policy")
		}
		for _, record := range records {
			if record != nil && string(record.DeviceID) == rejectedDevice {
				return errors.New("rejection identity already resolved")
			}
		}
	}
	state, e := migration.DecodeCertificates(rawState)
	if e != nil {
		return errors.New("original certificate observations unavailable")
	}
	if _, ok := state.Hosts[rejectedDevice]; ok {
		return errors.New("rejection identity already observed")
	}
	for _, h := range state.Hosts {
		if h.Observation != nil && slices.Contains(h.Observation.Fingerprints, fp) {
			return errors.New("rejection fingerprint already observed")
		}
	}
	for _, command := range state.Commands {
		if _, ok := command.Hosts[rejectedDevice]; ok {
			return errors.New("rejection identity in original pending command")
		}
	}
	return nil
}
