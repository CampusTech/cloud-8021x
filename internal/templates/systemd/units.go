// Package systemd owns the fixed installed privilege boundaries and jobs.
package systemd

func Render() (map[string][]byte, error) {
	files := map[string][]byte{}
	files["/etc/systemd/system/freeradius.service.d/accounting-key.conf"] = []byte("# Replaced by committed cloud-8021x credentials; legacy helper retirement is separate.\n")
	files["/etc/systemd/system/cloud-8021x.service"] = []byte(`[Unit]
Description=Cloud 802.1X policy and workers
Wants=network-online.target freeradius.service
After=network-online.target cloud-8021x-credentials.service cloud-8021x-metadata.service
Requires=cloud-8021x-credentials.service cloud-8021x-metadata.service
[Service]
Type=notify
NotifyAccess=main
TimeoutStartSec=30
User=cloud8021x
Group=cloud8021x
SupplementaryGroups=cloud8021x-events cloud8021x-spool-metadata
ExecStart=/usr/local/bin/cloud-8021x --config /etc/cloud-8021x/config.yaml serve
Restart=on-failure
RestartSec=5
UMask=0077
NoNewPrivileges=true
CapabilityBoundingSet=
AmbientCapabilities=
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
RestrictNamespaces=true
LockPersonality=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
ReadWritePaths=/var/lib/cloud-8021x /var/cache/cloud-8021x/runtime /run/radius-certificate-bindings
InaccessiblePaths=/etc/step-ca /etc/step-ca-rsa /run/cloud-8021x-root /run/cloud-8021x-collector /var/lib/cloud-8021x-bootstrap
MemoryMax=512M
TasksMax=128
TimeoutStopSec=20
[Install]
WantedBy=multi-user.target
`)
	files["/etc/systemd/system/cloud-8021x-credentials.service"] = []byte(`[Unit]
Description=Restore committed protected 802.1X credentials
Wants=network-online.target
After=network-online.target
Before=cloud-8021x.service freeradius.service step-ca.service step-ca-rsa.service
[Service]
Type=oneshot
ExecStart=/usr/local/bin/cloud-8021x --config /etc/cloud-8021x/config.yaml bootstrap credentials
RemainAfterExit=yes
UMask=0077
[Install]
WantedBy=multi-user.target
`)
	files["/etc/systemd/system/cloud-8021x-metadata.service"] = []byte(`[Unit]
Description=Block daemon metadata credentials while preserving DNS
Before=cloud-8021x.service
[Service]
Type=oneshot
ExecStart=/usr/sbin/nft --file /etc/cloud-8021x/metadata.nft
RemainAfterExit=yes
[Install]
WantedBy=multi-user.target
`)
	for _, name := range []string{"step-ca", "step-ca-rsa"} {
		files["/etc/systemd/system/"+name+".service"] = []byte(`[Unit]
Description=Smallstep certificate authority
After=network-online.target cloud-8021x-credentials.service cloud-8021x.service
Requires=cloud-8021x-credentials.service
[Service]
Environment=STEPPATH=/etc/` + name + `
Environment=STEP_LOGGER_LOG_REAL_IP=true
ExecStart=/usr/bin/step-ca /etc/` + name + `/config/ca.json
Restart=on-failure
RestartSec=5
UMask=0077
NoNewPrivileges=true
ProtectHome=true
PrivateTmp=true
ProtectSystem=strict
ReadWritePaths=/etc/` + name + `
MemoryMax=512M
[Install]
WantedBy=multi-user.target
`)
	}
	files["/etc/systemd/system/freeradius.service.d/cloud-8021x.conf"] = []byte(`[Unit]
After=cloud-8021x-credentials.service cloud-8021x.service
Requires=cloud-8021x-credentials.service cloud-8021x.service
BindsTo=cloud-8021x.service
[Service]
User=root
Group=root
Environment=
Environment=HOME=/nonexistent
ExecStartPre=
ExecStartPre=/usr/sbin/freeradius -XC
ExecStart=
ExecStart=/usr/sbin/freeradius -f
ExecReload=
NoNewPrivileges=false
CapabilityBoundingSet=CAP_CHOWN CAP_DAC_OVERRIDE CAP_SETUID CAP_SETGID
AmbientCapabilities=
ProtectHome=true
PrivateTmp=true
ProtectSystem=strict
ReadWritePaths=/run/freeradius /run/radius-verified-leaves /run/radius-certificate-bindings /var/log/freeradius /var/lib/cloud-8021x
UMask=0027
`)
	for name, command := range map[string]string{"renew": "certificates renew", "sources": "sources apply"} {
		files["/etc/systemd/system/cloud-8021x-"+name+".service"] = []byte(`[Unit]
Description=Protected cloud 802.1X ` + name + `
After=network-online.target cloud-8021x.service
[Service]
Type=oneshot
ExecStart=/usr/local/bin/cloud-8021x --config /etc/cloud-8021x/config.yaml ` + command + `
UMask=0077
TimeoutStartSec=5min
`)
		// Source scheduling is coordinated by Task9; the timer is installed disabled
		// until the durable claim binds candidate-sha256. No unclaimed apply timer.
		if name == "renew" {
			files["/etc/systemd/system/cloud-8021x-renew.timer"] = []byte(`[Unit]
Description=Check server certificate renewal
[Timer]
OnBootSec=15min
OnUnitActiveSec=1h
RandomizedDelaySec=5min
Persistent=true
[Install]
WantedBy=timers.target
`)
		}
	}
	files["/etc/systemd/system/var-lib-cloud8021x-collector.mount"] = []byte(`[Unit]
Description=Bounded persistent cloud 802.1X collector queue
Before=datadog-agent-ddot.service
[Mount]
What=/var/lib/cloud-8021x-bootstrap/collector.ext4
Where=/var/lib/cloud8021x/collector
Type=ext4
Options=loop,nodev,nosuid,noexec
[Install]
WantedBy=multi-user.target
`)
	files["/etc/systemd/system/datadog-agent.service.d/cloud-8021x.conf"] = []byte(`[Unit]
After=cloud-8021x-credentials.service
Requires=cloud-8021x-credentials.service
[Service]
EnvironmentFile=/run/cloud-8021x-collector/datadog.env
MemoryMax=768M
`)
	files["/etc/systemd/system/datadog-agent-ddot.service"] = []byte(`[Unit]
Description=Protected Datadog OpenTelemetry collector
After=datadog-agent.service cloud-8021x-credentials.service var-lib-cloud8021x-collector.mount
Requires=cloud-8021x-credentials.service var-lib-cloud8021x-collector.mount
[Service]
User=dd-agent
Group=dd-agent
ExecStart=/opt/datadog-agent/embedded/bin/otel-agent run --config /etc/cloud-8021x/ddot.yaml --core-config /etc/datadog-agent/datadog.yaml --pidfile /opt/datadog-agent/run/otel-agent.pid
EnvironmentFile=/run/cloud-8021x-collector/datadog.env
Restart=on-failure
RestartSec=2
UMask=0077
NoNewPrivileges=true
CapabilityBoundingSet=
AmbientCapabilities=
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
RestrictNamespaces=true
LockPersonality=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
ReadWritePaths=/var/lib/cloud8021x/collector /opt/datadog-agent/run
InaccessiblePaths=/etc/step-ca /etc/step-ca-rsa /run/cloud-8021x-root /run/cloud-8021x/credentials /var/lib/cloud-8021x-bootstrap
MemoryMax=768M
TasksMax=128
TimeoutStopSec=30
[Install]
WantedBy=multi-user.target
`)
	files["/etc/tmpfiles.d/cloud-8021x.conf"] = []byte(`d /run/cloud-8021x 0755 root root -
d /run/cloud-8021x/credentials 0700 cloud8021x cloud8021x -
d /run/cloud-8021x-root 0700 root root -
d /run/cloud-8021x-collector 0700 dd-agent dd-agent -
d /run/radius-verified-leaves 0700 freerad freerad -
d /run/radius-certificate-bindings 0700 cloud8021x cloud8021x -
d /run/freeradius 0755 freerad freerad -
d /var/log/freeradius/auth 2750 freerad cloud8021x-events -
d /var/log/freeradius/radacct 2750 freerad cloud8021x-spool-metadata -
`)
	files["/etc/sudoers.d/cloud-8021x"] = []byte("freerad ALL=(root) NOPASSWD: /usr/local/bin/cloud-8021x ^--config /etc/cloud-8021x/config\\.yaml radius verify-leaf /run/radius-verified-leaves/[A-Za-z0-9_.-]+ [0-9a-f]{64}$\n")
	return files, nil
}
