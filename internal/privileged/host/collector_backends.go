package host

import (
	"github.com/CampusTech/cloud-8021x/internal/config"
	"gopkg.in/yaml.v3"
)

// NativeCollectorFiles installs supported Agent checks even on a clean node.
// No check executes an exporter or reads a CA private configuration/key.
func NativeCollectorFiles(c config.Config, a Accounts) ([]File, error) {
	var files []File
	add := func(path string, instances []any) error {
		raw, err := yaml.Marshal(map[string]any{"init_config": map[string]any{}, "instances": instances})
		if err != nil {
			return err
		}
		files = append(files, File{Path: path, Data: raw, GID: a.CollectorGID, Mode: 0640, adoptUID: a.CollectorUID})
		return nil
	}
	var scrapes []any
	for _, ca := range []struct{ name, port, dns string }{{"ec", "9090", c.Bootstrap.ECDNS}, {"rsa", "9091", c.Bootstrap.RSADNS}} {
		metrics := []any{map[string]string{"step_ca_uptime_seconds": "uptime"}, map[string]string{"step_ca_x509_signed": "x509.signed"}, map[string]string{"step_ca_x509_webhook_authorized": "x509.webhook_authorized"}, map[string]string{"step_ca_x509_webhook_enriched": "x509.webhook_enriched"}, map[string]string{"step_ca_kms_signed": "kms.signed"}, map[string]string{"step_ca_kms_errors": "kms.errors"}}
		scrapes = append(scrapes, map[string]any{"openmetrics_endpoint": "http://127.0.0.1:" + ca.port + "/metrics", "namespace": "smallstep", "metrics": metrics, "tags": []string{"service:smallstep-ca", "ca_instance:" + ca.name}, "timeout": 2, "skip_proxy": true})
	}
	if err := add("/etc/datadog-agent/conf.d/openmetrics.d/stepca.yaml", scrapes); err != nil {
		return nil, err
	}
	// Retire the previous separately managed RSA config to avoid double collection.
	if err := add("/etc/datadog-agent/conf.d/openmetrics.d/stepca-rsa.yaml", []any{}); err != nil {
		return nil, err
	}

	var health []any
	for _, ca := range []struct{ name, instance, port, dns string }{{"ec", "stepca-health", "8443", c.Bootstrap.ECDNS}, {"rsa", "stepca-rsa-health", "8444", c.Bootstrap.RSADNS}} {
		health = append(health, map[string]any{"name": ca.instance, "url": "https://127.0.0.1:" + ca.port + "/health", "tls_verify": true, "tls_use_host_header": true, "headers": map[string]string{"Host": ca.dns}, "tls_ca_cert": "/etc/cloud-8021x/client-cas.pem", "check_certificate_expiration": false, "allow_redirects": false, "timeout": 2, "skip_proxy": true, "http_response_status_code": 200, "content_match": `"status"\s*:\s*"ok"`, "tags": []string{"service:smallstep-ca", "component:step-ca", "ca_instance:" + ca.name}})
	}
	if err := add("/etc/datadog-agent/conf.d/http_check.d/cloud-8021x.yaml", health); err != nil {
		return nil, err
	}
	if err := add("/etc/datadog-agent/conf.d/process.d/cloud-8021x.yaml", []any{
		map[string]any{"name": "freeradius", "search_string": []string{"freeradius"}, "exact_match": true, "collect_children": false, "service": "freeradius", "thresholds": map[string]any{"critical": []int{1, 1}}},
		map[string]any{"name": "step-ca", "search_string": []string{"step-ca"}, "exact_match": true, "collect_children": false, "service": "smallstep-ca", "thresholds": map[string]any{"critical": []int{2, 2}}},
	}); err != nil {
		return nil, err
	}
	return files, nil
}
