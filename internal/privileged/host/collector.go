package host

import (
	"bytes"
	"context"
	"errors"
	"os"
	"regexp"
	"strings"

	"github.com/CampusTech/cloud-8021x/internal/config"
	"github.com/CampusTech/cloud-8021x/internal/templates/ddot"
	"gopkg.in/yaml.v3"
)

const CollectorBinary = "/opt/datadog-agent/embedded/bin/otel-agent"
const CollectorQueue = "/var/lib/cloud8021x/collector/queue"
const CollectorMount = "var-lib-cloud8021x-collector.mount"
const collectorImage = transactionRoot + "/collector.ext4"
const collectorBytes = 512 << 20

func mergeAgentConfig(original []byte, site string) ([]byte, error) {
	values := map[string]any{}
	if len(bytes.TrimSpace(original)) > 0 {
		if err := yaml.Unmarshal(original, &values); err != nil || values == nil {
			return nil, errors.New("existing Agent config is malformed")
		}
	}
	var fragment map[string]any
	if err := yaml.Unmarshal([]byte(ddot.AgentFragment), &fragment); err != nil {
		return nil, err
	}
	for key, value := range fragment {
		values[key] = value
	}
	delete(values, "api_key") // Both Agent and DDOT receive the protected envfile.
	values["site"] = site
	return yaml.Marshal(values)
}
func CollectorEnvironment(key []byte, a Accounts) (File, error) {
	value := strings.TrimSpace(string(key))
	if !regexp.MustCompile(`^[A-Za-z0-9]{32,64}$`).MatchString(value) {
		return File{}, errors.New("collector API credential format rejected")
	}
	return File{Path: "/run/cloud-8021x-collector/datadog.env", Data: []byte("DD_API_KEY=" + value + "\n"), UID: a.CollectorUID, GID: a.CollectorGID, Mode: 0600}, nil
}
func CollectorFiles(c config.Config, key []byte, a Accounts) ([]File, error) {
	return collectorFiles(c, key, a, Snapshot)
}
func collectorFiles(c config.Config, key []byte, a Accounts, snapshot func(File) (SavedFile, error)) ([]File, error) {
	env, err := CollectorEnvironment(key, a)
	if err != nil {
		return nil, err
	}
	original, err := snapshot(File{Path: "/etc/datadog-agent/datadog.yaml", UID: a.CollectorUID})
	if err != nil {
		return nil, err
	}
	if !original.Exists {
		original.Data = []byte("hostname: " + c.Hostname + "\n")
	}
	merged, err := mergeAgentConfig(original.Data, c.Bootstrap.DatadogSite)
	if err != nil {
		return nil, err
	}
	collector, err := ddot.Render(ddot.Options{QueueDirectory: CollectorQueue, QueueBytes: 64 << 20, Site: c.Bootstrap.DatadogSite, LogsEndpoint: "https://otlp." + c.Bootstrap.DatadogSite + "/v1/logs"})
	if err != nil {
		return nil, err
	}
	files := []File{env, {Path: "/etc/datadog-agent/datadog.yaml", Data: merged, GID: a.CollectorGID, Mode: 0640, adoptUID: a.CollectorUID}, {Path: "/etc/cloud-8021x/ddot.yaml", Data: collector, GID: a.CollectorGID, Mode: 0640}}
	legacy, err := snapshot(File{Path: "/etc/datadog-agent/conf.d/freeradius.d/conf.yaml", UID: a.CollectorUID})
	if err != nil {
		return nil, err
	}
	if legacy.Exists {
		values := map[string]any{}
		if yaml.Unmarshal(legacy.Data, &values) != nil {
			return nil, errors.New("legacy Agent native integration malformed")
		}
		if logs, ok := values["logs"].([]any); ok {
			retained := []any{}
			for _, entry := range logs {
				row, ok := entry.(map[string]any)
				if !ok {
					return nil, errors.New("legacy native log entry malformed")
				}
				path, _ := row["path"].(string)
				switch path {
				case "/var/log/freeradius/radius-auth.json", "/var/log/freeradius/radius-acct.json", "/var/log/freeradius/source-discovery.log", "/var/log/radius-bootstrap.log":
					continue
				}
				retained = append(retained, entry)
			}
			values["logs"] = retained
		}
		data, err := yaml.Marshal(values)
		if err != nil {
			return nil, err
		}
		files = append(files, File{Path: "/etc/datadog-agent/conf.d/freeradius.d/conf.yaml", Data: data, GID: a.CollectorGID, Mode: 0640, adoptUID: a.CollectorUID})
	}
	nativeFiles, err := NativeCollectorFiles(c, a)
	if err != nil {
		return nil, err
	}
	return append(files, nativeFiles...), nil
}
func VerifyCollector(m Manifest) error {
	if !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(m.CollectorSHA256) {
		return errors.New("mandatory installed collector SHA missing")
	}
	digest, err := installedHash(CollectorBinary, 512<<20)
	if err != nil || digest != m.CollectorSHA256 {
		return errors.New("installed collector binary differs from protected manifest")
	}
	return nil
}

// This singleton queue is deliberately outside installation rollback: queued
// business records survive upgrades and failures. Existing image bytes are never
// formatted, truncated or replaced; interrupted initialization requires recovery.
func PrepareCollectorStorage(ctx context.Context) error {
	if os.Geteuid() != 0 {
		return errors.New("collector storage requires root")
	}
	if err := protectedDirectory(transactionRoot, 0, 0, 0700); err != nil {
		return err
	}
	existing, err := rootFile(collectorImage, collectorBytes)
	if errors.Is(err, os.ErrNotExist) {
		file, err := os.OpenFile(collectorImage, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
		if err != nil {
			return err
		}
		err = file.Truncate(collectorBytes)
		if err == nil {
			err = file.Sync()
		}
		err = errors.Join(err, file.Close())
		if err != nil {
			return err
		}
		directory, err := os.Open(transactionRoot)
		if err != nil {
			return err
		}
		err = directory.Sync()
		_ = directory.Close()
		if err != nil {
			return err
		}
		if _, err = execute(ctx, "/usr/sbin/mkfs.ext4", "-F", "-q", collectorImage); err != nil {
			return errors.New("collector filesystem initialization incomplete; existing image retained")
		}
	} else if err != nil {
		return err
	} else {
		info, err := existing.Stat()
		_ = existing.Close()
		if err != nil || info.Size() != collectorBytes || info.Mode().Perm() != 0600 {
			return errors.New("collector image identity rejected")
		}
	}
	image, err := rootFile(collectorImage, collectorBytes)
	if err != nil {
		return err
	}
	err = image.Sync()
	_ = image.Close()
	if err != nil {
		return err
	}
	kind, err := execute(ctx, "/usr/sbin/blkid", "-p", "-s", "TYPE", "-o", "value", collectorImage)
	if err != nil || strings.TrimSpace(string(kind)) != "ext4" {
		return errors.New("existing collector filesystem rejected; no reformat attempted")
	}
	return protectedDirectory("/var/lib/cloud8021x/collector", 0, 0, 0755)
}
func StartCollector(ctx context.Context, a Accounts) error {
	if _, err := execute(ctx, "/usr/bin/systemctl", "start", CollectorMount); err != nil {
		return err
	}
	if err := protectedDirectory(CollectorQueue, a.CollectorUID, a.CollectorGID, 0700); err != nil {
		return err
	}
	for _, unit := range []string{"datadog-agent.service", "datadog-agent-ddot.service"} {
		if _, err := execute(ctx, "/usr/bin/systemctl", "restart", unit); err != nil {
			return err
		}
	}
	return nil
}
func CollectorRunning(ctx context.Context) (bool, error) {
	out, err := execute(ctx, "/usr/bin/systemctl", "show", "datadog-agent-ddot.service", "--property=ActiveState", "--property=MainPID")
	if err != nil {
		return false, err
	}
	fields := map[string]string{}
	for _, line := range strings.Split(string(out), "\n") {
		key, value, _ := strings.Cut(line, "=")
		fields[key] = value
	}
	if fields["ActiveState"] == "active" && fields["MainPID"] != "" && fields["MainPID"] != "0" {
		return true, nil
	}
	if fields["ActiveState"] == "inactive" && fields["MainPID"] == "0" {
		return false, nil
	}
	return false, errors.New("collector process state unavailable")
}
