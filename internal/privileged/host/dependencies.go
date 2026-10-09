package host

import (
	"context"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"regexp"
	"strings"
)

// These are the signed Debian 13 runtime dependencies observed for the reviewed
// native family. They are not product packages or permission to upgrade the OS.
// In particular libc, libssl, systemd, apt, dpkg and kernels cannot be archives.
var dependencyArtifacts = []string{
	"adduser",
	"ca-certificates",
	"freetds-common",
	"libapparmor1",
	"libbrotli1",
	"libcom-err2",
	"libct4",
	"libcurl4t64",
	"libdbus-1-3",
	"libedit2",
	"libffi8",
	"libgdbm-compat4t64",
	"libgdbm6t64",
	"libgnutls30t64",
	"libgssapi-krb5-2",
	"libidn2-0",
	"libjansson4",
	"libjson-c5",
	"libk5crypto3",
	"libkeyutils1",
	"libkrb5-3",
	"libkrb5support0",
	"libldap2",
	"libmnl0",
	"libnftables1",
	"libnftnl11",
	"libnghttp2-14",
	"libnghttp3-9",
	"libp11-kit0",
	"libpcap0.8t64",
	"libperl5.40",
	"libpq5",
	"libpsl5t64",
	"libreadline8t64",
	"librtmp1",
	"libsasl2-2",
	"libsasl2-modules-db",
	"libsqlite3-0",
	"libssh2-1t64",
	"libtalloc2",
	"libtasn1-6",
	"libunistring5",
	"libwbclient0",
	"libxtables12",
	"make",
	"nftables",
	"openssl",
	"perl",
	"perl-modules-5.40",
	"readline-common",
	"ssl-cert",
	"sudo",
}

// These helpers touch host-wide accounts, trust, privilege or firewall policy.
// Initial installation is supported; replacing an existing older version needs
// separate OS/dependency preparation, not an application package transition.
var protectedBaseDependencies = []string{"adduser", "ca-certificates", "nftables", "openssl", "sudo"}

const maxForwardArtifacts = 64

type debPackage struct {
	Artifact
	Depends, PreDepends, Conflicts, Breaks, Provides string
}

type debRelation struct{ name, qualifier, operator, version string }

var relationPattern = regexp.MustCompile(`^([a-z0-9][a-z0-9+.-]{1,95})(?::(any|native))?(?:\s*\((<<|<=|=|>=|>>)\s*([a-zA-Z0-9][a-zA-Z0-9.+~:-]{0,95})\))?$`)

// Binary package control fields cannot contain build-profile or architecture
// restrictions. Reject unsupported syntax instead of inventing apt resolution.
func parseRelations(value string) ([][]debRelation, error) {
	if len(value) > 65536 {
		return nil, errors.New("oversized package relationships")
	}
	if strings.TrimSpace(value) == "" {
		return nil, nil
	}
	clauses := strings.Split(value, ",")
	if len(clauses) > 256 {
		return nil, errors.New("too many package relationships")
	}
	result := make([][]debRelation, 0, len(clauses))
	for _, clause := range clauses {
		choices := strings.Split(clause, "|")
		if len(choices) > 16 {
			return nil, errors.New("too many package alternatives")
		}
		var group []debRelation
		for _, choice := range choices {
			match := relationPattern.FindStringSubmatch(strings.TrimSpace(choice))
			if match == nil {
				return nil, fmt.Errorf("unsupported binary package relationship %q", strings.TrimSpace(choice))
			}
			group = append(group, debRelation{match[1], match[2], match[3], match[4]})
		}
		result = append(result, group)
	}
	return result, nil
}

type versionCompare func(version, operator, want string) bool

func packageSatisfies(p debPackage, r debRelation, arch string, compare versionCompare) (bool, error) {
	if p.Architecture != arch && p.Architecture != "all" {
		return false, nil
	}
	if p.Name == r.name && (r.operator == "" || compare(p.Version, r.operator, r.version)) {
		return true, nil
	}
	provided, err := parseRelations(p.Provides)
	if err != nil {
		return false, err
	}
	for _, group := range provided {
		if len(group) != 1 || group[0].qualifier != "" || (group[0].operator != "" && group[0].operator != "=") {
			return false, errors.New("unsupported package Provides")
		}
		offer := group[0]
		if offer.name == r.name && (r.operator == "" || offer.version != "" && compare(offer.version, r.operator, r.version)) {
			return true, nil
		}
	}
	return false, nil
}

// checkDependencies checks a chosen final inventory; it never chooses packages,
// resolves versions, fetches archives or permits unrelated base replacements.
func checkDependencies(packages map[string]debPackage, arch string, compare versionCompare) error {
	if len(packages) > 4096 {
		return errors.New("oversized installed package inventory")
	}
	for _, p := range packages {
		for _, field := range []struct {
			value    string
			conflict bool
		}{{p.Depends, false}, {p.PreDepends, false}, {p.Conflicts, true}, {p.Breaks, true}} {
			clauses, err := parseRelations(field.value)
			if err != nil {
				return fmt.Errorf("package %s: %w", p.Name, err)
			}
			for _, group := range clauses {
				matched := false
				for _, r := range group {
					for _, candidate := range packages {
						if field.conflict && candidate.Name == p.Name {
							continue
						}
						ok, err := packageSatisfies(candidate, r, arch, compare)
						if err != nil {
							return err
						}
						matched = matched || ok
					}
				}
				if matched == field.conflict {
					return fmt.Errorf("package %s dependency compatibility refused", p.Name)
				}
			}
		}
	}
	return nil
}

func readPackageInventory() (map[string]debPackage, error) {
	f, err := rootFile("/var/lib/dpkg/status", 4<<20)
	if err != nil {
		return nil, errors.New("installed package database unavailable")
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}
	result := map[string]debPackage{}
	for _, paragraph := range strings.Split(string(data), "\n\n") {
		fields := map[string]string{}
		last := ""
		for _, line := range strings.Split(paragraph, "\n") {
			if strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t") {
				fields[last] += " " + strings.TrimSpace(line)
				continue
			}
			key, value, ok := strings.Cut(line, ":")
			if !ok {
				continue
			}
			if _, duplicate := fields[key]; duplicate {
				return nil, errors.New("duplicate package status field")
			}
			fields[key] = strings.TrimSpace(value)
			last = key
		}
		name := fields["Package"]
		if name == "" {
			continue
		}
		switch fields["Status"] {
		case "deinstall ok config-files", "purge ok not-installed":
			continue
		case "install ok installed":
		default:
			return nil, errors.New("package database requires explicit recovery")
		}
		if _, duplicate := result[name]; duplicate {
			return nil, errors.New("ambiguous installed package identity")
		}
		if fields["Version"] == "" || fields["Architecture"] == "" {
			return nil, errors.New("incomplete installed package identity")
		}
		result[name] = debPackage{Artifact: Artifact{Name: name, Version: fields["Version"], Architecture: fields["Architecture"]}, Depends: fields["Depends"], PreDepends: fields["Pre-Depends"], Conflicts: fields["Conflicts"], Breaks: fields["Breaks"], Provides: fields["Provides"]}
	}
	return result, nil
}

func verifyPackageDependencies(ctx context.Context, incoming Manifest, retained map[string]Artifact) error {
	packages, err := readPackageInventory()
	if err != nil {
		return err
	}
	for _, a := range incoming.Artifacts {
		if old, keep := retained[a.Name]; keep {
			if !samePackage(old, packages[a.Name].Artifact) {
				return errors.New("retained dependency changed after preflight")
			}
			continue
		}
		path := filepath.Join(ArtifactDirectory, a.filename())
		out, err := execute(ctx, "/usr/bin/dpkg-deb", "--show", "--showformat=${Package}\x1e${Version}\x1e${Architecture}\x1e${Depends}\x1e${Pre-Depends}\x1e${Conflicts}\x1e${Breaks}\x1e${Provides}", path)
		if err != nil {
			return errors.New("package dependency metadata unavailable")
		}
		fields := strings.Split(string(out), "\x1e")
		if len(fields) != 8 || fields[0] != a.Name || fields[1] != a.Version || fields[2] != a.Architecture {
			return errors.New("package dependency metadata identity mismatch")
		}
		packages[a.Name] = debPackage{a, fields[3], fields[4], fields[5], fields[6], fields[7]}
	}
	for _, name := range retiredArtifacts {
		delete(packages, name)
	}
	return checkDependencies(packages, incoming.Architecture, debianCompare(ctx))
}

func debianCompare(ctx context.Context) versionCompare {
	cache := map[string]bool{}
	return func(version, operator, want string) bool {
		key := version + "\x00" + operator + "\x00" + want
		if value, ok := cache[key]; ok {
			return value
		}
		_, err := execute(ctx, "/usr/bin/dpkg", "--compare-versions", version, operator, want)
		cache[key] = err == nil
		return err == nil
	}
}
