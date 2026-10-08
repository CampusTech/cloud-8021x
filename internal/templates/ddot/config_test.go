package ddot

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestDedicatedDurablePipeline(t *testing.T) {
	b, err := Render(Options{Site: "us5.datadoghq.com", QueueDirectory: "/var/lib/cloud8021x/ddot", LogsEndpoint: "https://otlp.datadoghq.com/v1/logs", QueueBytes: 64 << 20})
	if err != nil {
		t.Fatal(err)
	}
	var c map[string]any
	if err = yaml.Unmarshal(b, &c); err != nil {
		t.Fatal(err)
	}
	pipeline := c["service"].(map[string]any)["pipelines"].(map[string]any)["logs/business"].(map[string]any)
	for _, p := range pipeline["processors"].([]any) {
		if strings.HasPrefix(p.(string), "batch") {
			t.Fatal("volatile prequeue batch")
		}
	}
	exporter := c["exporters"].(map[string]any)["otlp_http/business"].(map[string]any)
	if exporter["sending_queue"].(map[string]any)["storage"] != "file_storage/accounting" {
		t.Fatal("nonpersistent business exporter")
	}
	if strings.Contains(string(b), "filelog") || strings.Contains(string(b), "journald") {
		t.Fatal("duplicate remote collection")
	}
}
