package main

import (
	"errors"
	"path"
	"strings"

	seed "github.com/CampusTech/cloud-8021x/tests/runtime/task11-assembly-seed/contract"
)

type lowerEntry struct {
	Path, Kind, SHA256, Target string
	Mode                       uint32
	Bytes                      int64
}
type lowerManifest struct {
	Schema  int
	Entries []lowerEntry
}

func allowedLower(p string) bool {
	for _, prefix := range []string{"/usr/local", "/etc/ssh", "/etc/ssl/private", "/etc/cloud", "/etc/task11", "/etc/systemd/system", "/etc/rc", "/etc/freeradius", "/etc/step-ca", "/etc/acme-authz-webhook", "/etc/radius", "/etc/krb5.keytab", "/etc/datadog-agent", "/usr/sbin/policy-rc.d"} {
		if strings.HasPrefix(p, prefix) {
			return false
		}
	}
	for _, exact := range []string{"/etc/machine-id", "/etc/hostname", "/etc/hosts", "/etc/resolv.conf", "/etc/fstab", "/etc/crypttab", "/etc/shadow", "/etc/gshadow"} {
		if p == exact {
			return false
		}
	}
	return p == "/usr" || p == "/etc" || p == "/var" || p == "/var/lib" || p == "/var/lib/dpkg" || p == "/bin" || p == "/sbin" || p == "/lib" || p == "/lib64" || strings.HasPrefix(p, "/usr/") || strings.HasPrefix(p, "/etc/") || strings.HasPrefix(p, "/var/lib/dpkg/")
}
func (m lowerManifest) validate() error {
	if m.Schema != 1 || len(m.Entries) == 0 || len(m.Entries) > 200000 {
		return errors.New("bounded original lower projection required")
	}
	seen := map[string]bool{}
	var total int64
	for _, e := range m.Entries {
		if !allowedLower(e.Path) || path.Clean(e.Path) != e.Path || seen[e.Path] || (e.Kind != "symlink" && e.Mode&0022 != 0) {
			return errors.New("unapproved lower entry")
		}
		seen[e.Path] = true
		if e.Kind == "file" {
			if !seed.IsSHA(e.SHA256) || e.Bytes < 0 {
				return errors.New("unpinned lower file")
			}
			if e.Bytes > 1664*MiB-total {
				return errors.New("lower copy stream exceeds cap")
			}
			total += e.Bytes
		} else if e.Kind == "symlink" {
			target := e.Target
			if !path.IsAbs(target) {
				target = path.Join(path.Dir(e.Path), target)
			}
			if e.Target == "" || len(e.Target) > 4096 || !allowedLower(path.Clean(target)) {
				return errors.New("lower symlink escapes public projection")
			}
		} else if e.Kind != "directory" {
			return errors.New("device or special lower entry refused")
		}
	}
	if total > 1664*MiB {
		return errors.New("lower copy stream exceeds cap")
	}
	return nil
}
