package main

import (
	"fmt"
	"strconv"
	"strings"
)

func rootFor(n string) string { return platformRoot + "/roots/task11-" + n }
func nodeUnit(p plan, n node) string {
	var b strings.Builder
	fmt.Fprintf(&b, "[Unit]\nDescription=Owned Task11 %s namespace\nAfter=systemd-machined.service\nRequires=systemd-machined.service\n[Service]\nType=notify\nDelegate=yes\nKillMode=mixed\nTimeoutStopSec=30s\nTasksMax=256\nCPUQuota=100%%\nMemoryMax=768M\nDevicePolicy=closed\n", n.Name)
	args := "/usr/bin/systemd-nspawn --boot --keep-unit --register=yes --settings=no --link-journal=no --machine=task11-" + n.Name + " --hostname=task11-" + n.Name + " --directory=" + rootFor(n.Name) + " --network-namespace-path=/run/netns/" + n.Namespace
	if strings.HasPrefix(n.Name, "green-") {
		b.WriteString("DeviceAllow=/dev/loop-control rw\n")
		args += " --bind=/dev/loop-control"
		for _, d := range p.LoopDevices {
			b.WriteString("DeviceAllow=" + d + " rwm\n")
			args += " --bind=" + d
		}
	}
	// Each read-only public source is a single file. No private incoming directory is shared.
	args += " " + unitBind(p.Helpers["task11-cloud-contract"].Path, "/usr/local/libexec/task11-cloud-contract")
	fmt.Fprintf(&b, "ExecStart=%s\nSuccessExitStatus=133\nRestartForceExitStatus=133\nRestart=no\n", args)
	return b.String()
}
func completeNodeUnit(in inputs, n node) string {
	u := nodeUnit(in.Plan, n)
	var b strings.Builder
	for _, r := range in.Index.References[n.Name] {
		b.WriteString(" " + unitBind(r.Source, r.Destination))
	}
	if n.Name == "blue-primary" {
		b.WriteString(" " + unitBind(in.Plan.Helpers["task11-blue-migration"].Path, "/usr/local/libexec/task11-blue-migration"))
	}
	return strings.Replace(u, "\nSuccessExitStatus=133\n", b.String()+"\nSuccessExitStatus=133\n", 1)
}

// unitBind encodes two independent parsers: nspawn's colon-separated bind
// grammar consumes backslash escapes; ExecStart's C unescaping must preserve
// those backslashes in the argument handed to nspawn. Never change archive names.
func unitBind(source, destination string) string {
	escape := strings.NewReplacer(`\`, `\\`, `:`, `\:`)
	return strconv.Quote("--bind-ro=" + escape.Replace(source) + ":" + escape.Replace(destination))
}
func metadataUnit(n node) string {
	return "[Unit]\nDescription=Node-local synthetic metadata only\nBefore=network-online.target\n[Service]\nType=exec\nExecStart=/usr/local/libexec/task11-cloud-contract --fixture-root /var/lib/cloud8021x-task11-metadata --phase passive --metadata\nUser=root\nGroup=root\nNoNewPrivileges=yes\nProtectSystem=strict\nReadWritePaths=/var/lib/cloud8021x-task11-metadata\nMemoryMax=96M\nTasksMax=32\nRestart=no\n[Install]\nWantedBy=multi-user.target\n"
}
func apiUnit(gate string) string {
	root := originalRoot + "/api"
	if gate == "primitive" {
		root = controlRoot + "/primitive-api"
	}
	return fmt.Sprintf("[Unit]\nDescription=Owned Task11 %s remote contracts\n[Service]\nType=exec\nRootDirectory=%s/aux/api\nNetworkNamespacePath=/run/netns/c11-api\nBindReadOnlyPaths=%s/task11-cloud-contract:/usr/local/libexec/task11-cloud-contract\nBindPaths=%s:%s\nExecStart=/usr/local/libexec/task11-cloud-contract --fixture-root %s --phase active --listen 10.203.11.10:443\nUser=root\nGroup=root\nNoNewPrivileges=yes\nProtectSystem=strict\nReadWritePaths=%s\nMemoryMax=192M\nTasksMax=64\nRestart=no\n", gate, platformRoot, publicRoot, root, root, root, root)
}
func pgUnit() string {
	return fmt.Sprintf("[Unit]\nDescription=Owned Task11 verified-TLS PostgreSQL17\n[Service]\nType=exec\nRootDirectory=%s/aux/pg\nPrivateDevices=yes\nMountAPIVFS=yes\nNetworkNamespacePath=/run/netns/c11-pg\nUser=postgres\nGroup=postgres\nExecStart=/usr/lib/postgresql/17/bin/postgres -D /var/lib/postgresql/17/main -c config_file=/etc/task11-postgres/postgresql.conf -c unix_socket_directories=/var/lib/postgresql/run\nNoNewPrivileges=yes\nProtectSystem=strict\nReadWritePaths=/var/lib/postgresql\nMemoryMax=256M\nTasksMax=128\nRestart=no\n", platformRoot)
}
func localHosts(in inputs) []byte {
	var b strings.Builder
	b.WriteString("127.0.0.1 localhost\n169.254.169.254 metadata.google.internal\n")
	fmt.Fprintf(&b, "127.0.0.1 %s %s\n", in.Seed.ECDNS, in.Seed.RSADNS)
	b.WriteString("10.203.11.10 secretmanager.googleapis.com cloudkms.googleapis.com sqladmin.googleapis.com fleet.task11.test otlp.us5.datadoghq.com otlp.task11.test unifi.task11.test\n")
	for _, n := range in.Plan.Nodes {
		fmt.Fprintf(&b, "%s task11-%s\n", n.Address, n.Name)
	}
	return []byte(b.String())
}
