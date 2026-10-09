package app

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/adapters/stepca"
	"github.com/CampusTech/cloud-8021x/internal/config"
	"github.com/CampusTech/cloud-8021x/internal/events/auth"
	"github.com/CampusTech/cloud-8021x/internal/telemetry"
)

type certificateExpiry struct {
	Component, Cert, CA string
	Days                float64
}

func observeCertificateFiles(now time.Time, read func(string, bool, int64) ([]byte, error)) []certificateExpiry {
	var out []certificateExpiry
	for _, item := range []struct{ path, component, cert, ca string }{
		{"/etc/cloud-8021x/radius-server.pem", "freeradius", "server", "ec"},
		{"/etc/cloud-8021x/ec-intermediate.pem", "step-ca", "intermediate", "ec"},
		{"/etc/cloud-8021x/rsa-intermediate.pem", "step-ca", "intermediate", "rsa"},
		{"/etc/cloud-8021x/ec-decrypter.pem", "step-ca", "decrypter", "ec"},
		{"/etc/cloud-8021x/rsa-decrypter.pem", "step-ca", "decrypter", "rsa"},
	} {
		raw, err := read(item.path, false, 1<<20)
		if err != nil {
			continue
		}
		block, _ := pem.Decode(raw)
		if block == nil || block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}
		out = append(out, certificateExpiry{item.component, item.cert, item.ca, cert.NotAfter.Sub(now).Hours() / 24})
	}
	return out
}
func observeSCEP(ctx context.Context, c config.Config) bool {
	trust, err := readInventoryFile("/etc/cloud-8021x/client-cas.pem", false, 1<<20)
	if err != nil {
		return false
	}
	decrypter, err := readInventoryFile("/etc/cloud-8021x/rsa-decrypter.pem", false, 1<<20)
	if err != nil {
		return false
	}
	return stepca.ProbeSCEPDecrypter(ctx, "127.0.0.1:8444", c.Bootstrap.RSADNS, c.Bootstrap.SCEPProvisioner, trust, decrypter) == nil
}
func emitObservations(ctx context.Context, m *telemetry.Measurements, c config.Config, ob diagnosticObservation) {
	for name, state := range ob.Components {
		value := 0.0
		if state == "ready" || state == "running" {
			value = 1
		}
		m.ObserveComponent(ctx, "backend.up", name, value)
	}
	for name, value := range ob.Measurements {
		m.ObserveCluster(ctx, name, c.StateTransition, value)
	}
	for _, cert := range ob.Certificates {
		m.CertificateExpiry(ctx, cert.Component, cert.Cert, cert.CA, cert.Days)
	}
	if ob.ClientExpiring != nil {
		m.ClientExpiry(ctx, c.StateTransition, *ob.ClientExpiring)
	}
	m.SCEPReady(ctx, ob.SCEPReady)
	m.NativeStatistics(ob.NativeStatistics)
}

func clientCertificateIssuers() map[string]string {
	return clientCertificateIssuerFiles(readInventoryFile)
}
func clientCertificateIssuerFiles(read func(string, bool, int64) ([]byte, error)) map[string]string {
	result := map[string]string{}
	for _, ca := range []string{"ec", "rsa"} {
		raw, err := read("/etc/cloud-8021x/"+ca+"-intermediate.pem", false, 1<<20)
		if err != nil {
			return nil
		}
		name, err := auth.NativeIssuerName(raw)
		if err != nil {
			return nil
		}
		if _, duplicate := result[name]; duplicate {
			result[name] = "wifi"
		} else {
			result[name] = ca
		}
	}
	return result
}
