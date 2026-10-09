// Package ddot owns Datadog-specific routing at the export edge. The core Agent
// continues host/FreeRADIUS checks; no application file/journal tailer is installed.
package ddot

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"errors"
	"net/url"
	"path/filepath"
	"text/template"
)

//go:embed collector.yaml.tmpl
var collector string

type Options struct {
	QueueDirectory, LogsEndpoint, Site string
	QueueBytes                         int64
}

func Render(o Options) ([]byte, error) {
	u, err := url.Parse(o.LogsEndpoint)
	if o.Site != "datadoghq.com" && o.Site != "us3.datadoghq.com" && o.Site != "us5.datadoghq.com" && o.Site != "datadoghq.eu" && o.Site != "ap1.datadoghq.com" && o.Site != "ap2.datadoghq.com" {
		return nil, errors.New("invalid Datadog site")
	}
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || !filepath.IsAbs(o.QueueDirectory) || filepath.Clean(o.QueueDirectory) != o.QueueDirectory || o.QueueBytes < 1<<20 || o.QueueBytes > 1<<30 {
		return nil, errors.New("invalid DDOT configuration")
	}
	t, err := template.New("collector").Funcs(template.FuncMap{"quote": func(s string) string { b, _ := json.Marshal(s); return string(b) }}).Parse(collector)
	if err != nil {
		return nil, err
	}
	var b bytes.Buffer
	err = t.Execute(&b, o)
	return b.Bytes(), err
}

// AgentFragment must be merged into the existing Agent config by the installer,
// not substituted for its host/integration configuration. Restrict converter
// features so automatic host enrichment cannot overwrite original producers.
const AgentFragment = `auth_token_file_path: /opt/datadog-agent/run/auth_token
ipc_cert_file_path: /opt/datadog-agent/run/ipc_cert.pem
disable_file_logging: true
log_to_console: true
remote_configuration:
  enabled: false
otelcollector:
  enabled: true
  converter:
    features: [ddflare]
logs_enabled: true
`
