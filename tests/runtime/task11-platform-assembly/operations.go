package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/CampusTech/cloud-8021x/internal/domain"
)

type operation struct {
	planSHA string
	in      inputs
	r       runner
	ctx     context.Context
}

func (o operation) call(name string, args ...string) error {
	_, e := o.r.call(o.ctx, name, args...)
	return e
}
func (o operation) filesystem(name string, size int64) (string, error) {
	steps, e := filesystemSteps(name, size)
	if e != nil {
		return "", e
	}
	image := platformRoot + "/images/" + name + ".ext4"
	target := platformRoot + "/volumes/" + name
	if e = publish(image, nil, 0600); e != nil {
		return "", e
	}
	if e = directory(target, 0700); e != nil {
		return "", e
	}
	for _, step := range steps {
		if e = o.call(step.Name, step.Args...); e != nil {
			return "", e
		}
	}
	return target, nil
}
func (o operation) lower() error {
	raw, e := readPinned(controlRoot+"/lower-source.json", o.in.Plan.LowerManifestSHA256, 32<<20, true)
	if e != nil {
		return e
	}
	var m lowerManifest
	if domain.DecodeJSONStrict(raw, &m) != nil {
		return errors.New("strict measured lower source required")
	}
	if e = m.validate(); e != nil {
		return e
	}
	lower, e := o.filesystem("lower", 1792*MiB)
	if e != nil {
		return e
	}
	// Directories precede leaves; no source links are followed while copying.
	sort.Slice(m.Entries, func(i, j int) bool {
		a, b := m.Entries[i], m.Entries[j]
		if (a.Kind == "directory") != (b.Kind == "directory") {
			return a.Kind == "directory"
		}
		return a.Path < b.Path
	})
	for _, v := range m.Entries {
		target := lower + v.Path
		switch v.Kind {
		case "directory":
			e = directory(target, v.Mode)
		case "file":
			e = copyPinnedFile(v.Path, target, v.SHA256, v.Bytes, v.Mode)
		case "symlink":
			actual, er := os.Readlink(v.Path)
			if er != nil || actual != v.Target {
				return errors.New("lower source symlink changed")
			}
			e = linkFile(target, v.Target)
		}
		if e != nil {
			return e
		}
	}
	for _, d := range []string{"/dev", "/proc", "/sys", "/run", "/tmp", "/var/tmp", "/var/log", "/var/cache", "/root", "/etc/systemd/system", "/etc/ssl/private"} {
		if e = directory(lower+d, 0755); e != nil {
			return e
		}
	}
	for _, f := range []string{"shadow", "gshadow"} {
		b, er := os.ReadFile(lower + "/etc/" + map[string]string{"shadow": "passwd", "gshadow": "group"}[f])
		if er != nil {
			return er
		}
		var locked strings.Builder
		for _, line := range strings.Split(string(b), "\n") {
			if line != "" {
				name := strings.SplitN(line, ":", 2)[0]
				if f == "shadow" {
					fmt.Fprintf(&locked, "%s:!:0:0:99999:7:::\n", name)
				} else {
					fmt.Fprintf(&locked, "%s:!::\n", name)
				}
			}
		}
		if e = publish(lower+"/etc/"+f, []byte(locked.String()), 0600); e != nil {
			return e
		}
	}
	if e = publish(lower+"/usr/sbin/policy-rc.d", []byte("#!/bin/sh\nexit 101\n"), 0755); e != nil {
		return e
	}
	args := lowerInstallArgs(o.in)
	if e = o.call("systemd-run", args...); e != nil {
		return e
	}

	b, e := o.r.call(o.ctx, "dpkg", "--root="+lower, "--audit")
	if e != nil || len(strings.TrimSpace(string(b))) != 0 {
		return errors.New("installed lower package audit failed")
	}

	// Package post-installers can create private runtime material. It cannot be
	// inherited by any node. Remove only this newly created owned lower's fixed
	// mutable identity/state locations; green prepare owns their later publication.
	for _, rel := range []string{"/etc/machine-id", "/etc/freeradius/3.0/certs", "/etc/datadog-agent/auth_token", "/etc/datadog-agent/ipc_cert.pem", "/var/lib/datadog-agent", "/var/lib/freeradius", "/var/lib/postgresql", "/var/log", "/etc/systemd/system/multi-user.target.wants", "/etc/systemd/system/timers.target.wants"} {
		if e = os.RemoveAll(lower + rel); e != nil {
			return e
		}
	}
	if e = checkInstalledFootprint(lower, o.in.Plan.Budget.LowerBytes); e != nil {
		return e
	}
	return o.call("mount", "-o", "remount,ro,nodev", lower)
}
func (o operation) overlay(name, target string, size int64) error {
	volume, e := o.filesystem(name, size)
	if e != nil {
		return e
	}
	for _, d := range []string{volume + "/upper", volume + "/work", target} {
		if e = directory(d, 0700); e != nil {
			return e
		}
	}
	options := "lowerdir=" + platformRoot + "/volumes/lower,upperdir=" + volume + "/upper,workdir=" + volume + "/work"
	return o.call("mount", "-t", "overlay", "overlay", "-o", options, target)
}
func (o operation) network() error {
	rules, e := bridgeRules(o.in.Plan)
	if e != nil {
		return e
	}
	if _, e = executePinned(o.ctx, o.in.Plan.Tools["nft"], []string{"-f", "-"}, []byte(rules)); e != nil {
		return e
	}
	if e = o.call("ip", "link", "add", "c8021x11", "type", "bridge"); e != nil {
		return e
	}
	for _, ep := range endpoints(o.in.Plan) {
		for _, args := range [][]string{{"netns", "add", ep.Name}, {"link", "add", ep.Name + "-h", "type", "veth", "peer", "name", ep.Name + "-n"}, {"link", "set", ep.Name + "-n", "netns", ep.Name}, {"link", "set", ep.Name + "-h", "master", "c8021x11"}, {"-n", ep.Name, "link", "set", ep.Name + "-n", "name", "eth0"}, {"-n", ep.Name, "address", "add", ep.Address + "/24", "dev", "eth0"}} {
			if e = o.call("ip", args...); e != nil {
				return e
			}
		}
		// Install deny-by-default rules before either veth end is brought up.
		rulesPath := controlRoot + "/network/" + ep.Name + ".nft"
		if e = publish(rulesPath, []byte(namespaceRules(o.in.Plan, ep.Address)), 0600); e != nil {
			return e
		}
		if e = o.call("ip", "netns", "exec", ep.Name, o.in.Plan.Tools["nft"].Path, "-f", rulesPath); e != nil {
			return e
		}
		if e = o.call("ip", "netns", "exec", ep.Name, o.in.Plan.Tools["sysctl"].Path, "-qw", "net.ipv6.conf.all.disable_ipv6=1", "net.ipv4.ip_forward=0"); e != nil {
			return e
		}
		for _, args := range [][]string{{"-n", ep.Name, "link", "set", "lo", "up"}, {"-n", ep.Name, "link", "set", "eth0", "up"}, {"link", "set", ep.Name + "-h", "up"}} {
			if e = o.call("ip", args...); e != nil {
				return e
			}
		}
		if strings.HasPrefix(ep.Name, "c11-b") || strings.HasPrefix(ep.Name, "c11-g") {
			if e = o.call("ip", "-n", ep.Name, "address", "add", "169.254.169.254/32", "dev", "lo"); e != nil {
				return e
			}
		}
	}
	return o.call("ip", "link", "set", "c8021x11", "up")
}
func checkInstalledFootprint(root string, ceiling int64) error {
	var total int64
	var count int
	e := filepath.Walk(root, func(_ string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		count++
		if info.Mode().IsRegular() {
			total += info.Size()
		}
		if total > ceiling || count > 200000 {
			return errors.New("measured installed layer exceeds reviewed bytes/inodes")
		}
		return nil
	})
	return e
}

func (o operation) bindPublic(p pin, target string) error {
	f, e := openPinned(p.Path, p.SHA256, 160<<20, false)
	if e != nil {
		return e
	}
	defer func() { _ = f.Close() }()
	st, e := f.Stat()
	if e != nil || st.Mode().Perm()&0111 == 0 {
		return errors.New("public helper is not executable")
	}
	if _, e = os.Lstat(target); os.IsNotExist(e) {
		if e = publish(target, nil, 0755); e != nil {
			return e
		}
	} else {
		old, e := openPinned(target, p.SHA256, 160<<20, false)
		if e != nil {
			return errors.New("preexisting helper differs")
		}
		_ = old.Close()
	}
	// Tool FD3 and source FD4 remain checked/open through mount; canonicalization
	// must not reopen the source pathname after the hash check.
	if _, e = executeWithFiles(o.ctx, o.in.Plan.Tools["mount"], []string{"--no-canonicalize", "--bind", "/proc/self/fd/4", target}, nil, []*os.File{f}); e != nil {
		return e
	}
	return o.call("mount", "-o", "remount,bind,ro", target)
}

func lowerInstallArgs(in inputs) []string {
	args := []string{"--unit=task11-lower-install", "--collect", "--quiet", "--wait", "--pipe", "--service-type=exec", "--property=RootDirectory=" + platformRoot + "/volumes/lower", "--property=PrivateDevices=yes", "--property=MountAPIVFS=yes", "--property=PrivateNetwork=yes", "--property=RuntimeMaxSec=180", "--property=TimeoutStopSec=5", "--property=KillMode=control-group", "--property=MemoryMax=512M", "--property=TasksMax=256", "--property=BindReadOnlyPaths=" + publicRoot + "/artifacts:/run/task11-artifacts", "/usr/bin/dpkg", "--install"}
	for _, a := range in.Packages.Artifacts {
		args = append(args, "/run/task11-artifacts/"+a.Name+"_"+a.Version+"_"+a.Architecture+".deb")
	}
	return args
}
