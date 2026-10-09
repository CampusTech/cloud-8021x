package host

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestCollectorAgentMergePreservesHostChecksAndScopesSecrets(t *testing.T) {
	original := []byte("hostname: campus-primary\nsite: us5.datadoghq.com\napi_key: sentinel-private-api-key\ntags: [environment:production]\nprocess_config:\n  process_collection:\n    enabled: true\n")
	merged, err := mergeAgentConfig(original, "us5.datadoghq.com")
	if err != nil {
		t.Fatal(err)
	}
	var values map[string]any
	if err = yaml.Unmarshal(merged, &values); err != nil {
		t.Fatal(err)
	}
	if values["hostname"] != "campus-primary" || values["process_config"] == nil || values["tags"] == nil || strings.Contains(string(merged), "sentinel-private") {
		t.Fatal("host checks or secret boundary changed")
	}
	if !strings.Contains(string(merged), "ddflare") {
		t.Fatal("missing tested converter restriction")
	}
	if _, err = mergeAgentConfig([]byte("hostname: [invalid"), "us5.datadoghq.com"); err == nil {
		t.Fatal("malformed prior Agent config replaced")
	}
}

func TestCollectorCoreIPCUsesPrivateWritableRuntimeDirectory(t *testing.T) {
	merged, err := mergeAgentConfig([]byte("hostname: preserved\ntags: [site:preserved]\n"), "us5.datadoghq.com")
	if err != nil {
		t.Fatal(err)
	}
	var values map[string]any
	if err = yaml.Unmarshal(merged, &values); err != nil {
		t.Fatal(err)
	}
	if values["auth_token_file_path"] != "/opt/datadog-agent/run/auth_token" || values["ipc_cert_file_path"] != "/opt/datadog-agent/run/ipc_cert.pem" || values["disable_file_logging"] != true || values["log_to_console"] != true {
		t.Fatal("unprivileged Agent/DDOT cannot create shared IPC material or logs in protected config directories")
	}
}
