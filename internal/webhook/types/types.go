// Package types mirrors the step-ca webhook request/response contract
// (smallstep/certificates/webhook). Only the fields we need are included.
package types

import "time"

// AttestationData carries the device's verified permanent identifier (serial)
// from an ACME device-attest-01 challenge.
type AttestationData struct {
	PermanentIdentifier string `json:"permanentIdentifier"`
}

// SCEPCertificateRequestSubject is the parsed CSR subject step-ca sends in a
// SCEP webhook request; we only need the CommonName (it carries the serial).
type SCEPCertificateRequestSubject struct {
	CommonName string `json:"commonName"`
}

// X509CertificateRequest is the CSR step-ca sends in a SCEP webhook request.
type X509CertificateRequest struct {
	Subject SCEPCertificateRequestSubject `json:"subject"`
}

// RequestBody is the payload step-ca POSTs to an AUTHORIZING webhook.
type RequestBody struct {
	Timestamp              time.Time               `json:"timestamp"`
	ProvisionerName        string                  `json:"provisionerName,omitempty"`
	AttestationData        *AttestationData        `json:"attestationData,omitempty"`
	SCEPChallenge          string                  `json:"scepChallenge,omitempty"`
	SCEPTransactionID      string                  `json:"scepTransactionID,omitempty"`
	X509CertificateRequest *X509CertificateRequest `json:"x509CertificateRequest,omitempty"`
}

// ResponseBody is what step-ca expects back. Allow must be true to sign.
type ResponseBody struct {
	Allow bool   `json:"allow"`
	Error string `json:"error,omitempty"`
}
