package telemetry

import (
	"context"
	"math"
	"strings"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

// CertificateExpiry retains negative days for already-expired certificates.
// All labels are closed categories, never certificate subjects or device IDs.
func (x *Measurements) CertificateExpiry(ctx context.Context, component, cert, ca string, days float64) {
	if math.IsNaN(days) || math.IsInf(days, 0) || (ca != "ec" && ca != "rsa") {
		return
	}
	supported := (component == "freeradius" && cert == "server" && ca == "ec") || (component == "step-ca" && (cert == "intermediate" || cert == "decrypter"))
	if !supported {
		return
	}
	x.gauges["certificate.days_until_expiry"].Record(ctx, days, metric.WithAttributes(attribute.String("component", component), attribute.String("cert", cert), attribute.String("ca_instance", ca)))
}
func (x *Measurements) ClientExpiry(ctx context.Context, cluster string, count int) {
	if count < 0 || len(cluster) != 64 || strings.Trim(cluster, "0123456789abcdef") != "" {
		return
	}
	x.gauges["client_certificate.expiring_soon"].Record(ctx, float64(count), metric.WithAttributes(attribute.String("component", "freeradius"), attribute.String("window", "48h"), attribute.String("scope", "shared"), attribute.String("cluster", cluster)))
}
func (x *Measurements) SCEPReady(ctx context.Context, ready bool) {
	value := 0.0
	if ready {
		value = 1
	}
	x.gauges["scep.decrypter_ready"].Record(ctx, value, metric.WithAttributes(attribute.String("component", "step-ca"), attribute.String("ca_instance", "rsa")))
}
