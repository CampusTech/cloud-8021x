package main

import (
	"bytes"
	"errors"
	"path"
	"sort"
	"strings"
	"unicode"

	"github.com/CampusTech/cloud-8021x/internal/adapters/freeradius/native"
	"github.com/CampusTech/cloud-8021x/internal/adoption"
	"github.com/CampusTech/cloud-8021x/internal/templates/systemd"
	seed "github.com/CampusTech/cloud-8021x/tests/runtime/task11-assembly-seed/contract"
	"gopkg.in/yaml.v3"
)

func sourceUnits() map[string][]byte {
	files, _ := systemd.Render()
	out := map[string][]byte{"/etc/sudoers.d/cloud-8021x": files["/etc/sudoers.d/cloud-8021x"]}
	nativeUnit := string(files["/etc/systemd/system/freeradius.service.d/cloud-8021x.conf"])
	nativeUnit = strings.ReplaceAll(nativeUnit, "cloud-8021x-credentials.service", "systemd-tmpfiles-setup.service")
	nativeUnit = strings.ReplaceAll(nativeUnit, "cloud-8021x.service", "task11-source-policy.service")
	out["/etc/systemd/system/freeradius.service.d/cloud-8021x.conf"] = []byte(nativeUnit)
	for _, name := range []string{"step-ca", "step-ca-rsa"} {
		out["/etc/systemd/system/"+name+".service"] = []byte(`[Unit]
Description=Task11 synthetic original CA using shipping executable
After=network-online.target systemd-tmpfiles-setup.service acme-authz-webhook.service
Requires=acme-authz-webhook.service
[Service]
Environment=STEPPATH=/etc/` + name + `
ExecStart=/usr/bin/step-ca /etc/` + name + `/config/ca.json
Restart=on-failure
UMask=0077
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=/etc/` + name + `
[Install]
WantedBy=multi-user.target
`)
	}
	out["/etc/systemd/system/task11-source-policy.service"] = []byte(`[Unit]
Description=Task11 synthetic legacy-compatible source policy
After=network.target systemd-tmpfiles-setup.service
[Service]
User=cloud8021x
Group=cloud8021x
ExecStart=/usr/local/libexec/task11-acceptance source-policy
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/run/radius-certificate-bindings
Restart=on-failure
[Install]
WantedBy=multi-user.target
`)
	out["/etc/systemd/system/acme-authz-webhook.service"] = []byte(`[Unit]
Description=Task11 original webhook using shipping compatibility entrypoint
After=network-online.target
[Service]
User=cloud8021x
Group=cloud8021x
EnvironmentFile=/etc/cloud8021x-task11-webhook.env
ExecStart=/usr/local/bin/acme-authz-webhook serve
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
Restart=on-failure
[Install]
WantedBy=multi-user.target
`)
	out["/etc/systemd/system/radius-source-refresh.service"] = []byte("[Unit]\nDescription=Task11 synthetic source writer workload\n[Service]\nType=oneshot\nExecStart=/usr/local/libexec/task11-acceptance source-writer\n")
	out["/etc/systemd/system/radius-source-refresh.timer"] = []byte("[Unit]\nDescription=Task11 synthetic source writer timer\n[Timer]\nOnBootSec=10s\nOnUnitActiveSec=10s\nUnit=radius-source-refresh.service\n[Install]\nWantedBy=timers.target\n")
	return out
}
func envLine(name string, value []byte) (string, error) {
	if strings.IndexFunc(string(value), unicode.IsControl) >= 0 || len(value) == 0 || len(value) > 8192 {
		return "", errors.New("bounded single-line environment value required")
	}
	// EnvironmentFile double quotes process these shell-like escapes, without variable expansion.
	v := strings.NewReplacer("\\", "\\\\", "\"", "\\\"", "$", "\\$", "`", "\\`").Replace(string(value))
	return name + "=\"" + v + "\"\n", nil
}
func sourceCandidates(s seed.Input, files map[string][]byte, role, _ string) (map[string]candidate, error) {
	if err := validateOriginalFiles(files); err != nil {
		return nil, err
	}
	c, err := sourceConfig(s, role)
	if err != nil {
		return nil, err
	}
	values, err := secretValues(s, files["api/seed.json"], true)
	if err != nil {
		return nil, err
	}
	rendered, err := native.RenderWithSecretsAndDatabaseCA(c, "7a5110a161a10001", values, files[s.PostgresCA.Path])
	if err != nil {
		return nil, err
	}
	out := map[string]candidate{}
	put := func(dst string, b []byte, owner, group string, mode uint32) {
		out[dst] = candidate{bytes.Clone(b), adoption.Digest(b), owner, group, mode}
	}
	for name, b := range files {
		if strings.HasPrefix(name, "source/") {
			dst := strings.TrimPrefix(name, "source")
			owner, group, mode := "root", "root", uint32(0600)
			switch {
			case dst == "/etc/cloud8021x-task11-source-provenance.json":
				mode = 0444
			case dst == "/etc/freeradius/3.0/device-policy-cache.json":
				group = "freerad"
				mode = 0644
			case strings.HasPrefix(dst, "/etc/freeradius/3.0/certs/"):
				group = "freerad"
				mode = 0640
			case strings.HasPrefix(dst, "/etc/acme-authz-webhook/"):
				group = "cloud8021x"
				mode = 0640
			case dst == "/run/radius-accounting-key":
				owner = "cloud8021x"
				group = "cloud8021x"
			}
			put(dst, b, owner, group, mode)
		}
	}
	// Preserve the original filename for source capture and supply the shipping native path.
	put(c.CA.ServerCertFile, files["source/etc/freeradius/3.0/certs/server.pem"], "root", "freerad", 0640)
	trust := files["source/etc/freeradius/3.0/certs/ca.pem"]
	put("/etc/cloud-8021x/client-cas.pem", trust, "root", "root", 0644)
	put("/etc/acme-authz-webhook/client-cas.pem", trust, "root", "root", 0644)
	for rel, b := range rendered {
		if path.IsAbs(rel) || path.Clean(rel) != rel || strings.HasPrefix(rel, "../") {
			return nil, errors.New("native renderer returned unsafe relative file")
		}
		put("/etc/freeradius/3.0/"+rel, b, "root", "freerad", 0640)
	}
	raw, err := yaml.Marshal(c)
	if err != nil {
		return nil, err
	}
	put("/etc/cloud8021x-task11-source.yaml", raw, "root", "cloud8021x", 0640)
	put("/etc/cloud-8021x/config.yaml", raw, "root", "cloud8021x", 0640)
	tmp := "d /run/cloud-8021x 0755 root root -\nd /run/cloud-8021x/credentials 0700 cloud8021x cloud8021x -\nd /run/cloud-8021x-root 0700 root root -\nd /run/cloud-8021x-collector 0700 dd-agent dd-agent -\nd /run/radius-certificate-bindings 0700 cloud8021x cloud8021x -\nd /run/radius-verified-leaves 0700 freerad freerad -\n"
	for _, ref := range s.Credentials {
		owner := map[string]string{"runtime": "cloud8021x", "root": "root", "collector": "dd-agent"}[ref.Owner]
		dst := ref.File
		persist := "/etc/cloud8021x-task11-credentials/" + path.Base(dst)
		put(dst, values[dst], owner, owner, 0600)
		put(persist, values[dst], "root", "root", 0600)
		tmp += "C " + dst + " 0600 " + owner + " " + owner + " - " + persist + "\n"
	}
	class := files["source/run/radius-accounting-key"]
	persist := "/etc/cloud8021x-task11-credentials/legacy-class"
	put(persist, class, "root", "root", 0600)
	tmp += "C /run/radius-accounting-key 0600 cloud8021x cloud8021x - " + persist + "\n"
	put("/etc/tmpfiles.d/task11-source.conf", []byte(tmp), "root", "root", 0644)
	env := map[string][]byte{"PORT": []byte("9444"), "WEBHOOK_CLIENT_DNS_NAMES": []byte(s.ECDNS + "," + s.RSADNS), "FLEET_API_BASE_URL": []byte("https://fleet.task11.test"), "FLEET_API_TOKEN": values[c.Inventory.Fleet.ObserverToken.File], "SCEP_CHALLENGE_SIGNING_KEY": values[c.Inventory.Fleet.ChallengeSigningKey.File], "SCEP_CERTIFICATE_INVENTORY": []byte("true"), "SCEP_BROKER_USERNAME": []byte("fleet"), "SCEP_BROKER_TOKEN": values[c.Listeners.Broker.Token.File], "SCEP_BROKER_SCEP_URL": []byte(c.Listeners.Broker.SCEPURL), "SCEP_BROKER_PROVISIONER": []byte("wifi-scep")}
	keys := make([]string, 0, len(env))
	for k := range env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var envBytes strings.Builder
	for _, k := range keys {
		line, err := envLine(k, env[k])
		if err != nil {
			return nil, err
		}
		envBytes.WriteString(line)
	}
	put("/etc/cloud8021x-task11-webhook.env", []byte(envBytes.String()), "root", "root", 0600)
	for dst, b := range sourceUnits() {
		mode := uint32(0644)
		if strings.HasPrefix(dst, "/etc/sudoers") {
			mode = 0440
		}
		put(dst, b, "root", "root", mode)
	}
	return out, nil
}
