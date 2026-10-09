package host

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

const rollbackArtifactDirectory = ArtifactDirectory + "/rollback"

type PackagePlan struct {
	Incoming  Manifest            `json:"incoming"`
	Previous  []Artifact          `json:"previous"`
	Absent    []string            `json:"originally_absent"`
	Installed map[string]Artifact `json:"installed"`
	Retired   []string            `json:"retired,omitempty"`
	Changed   bool                `json:"changed"`
}

func samePackage(a, b Artifact) bool {
	return a.Name == b.Name && a.Version == b.Version && a.Architecture == b.Architecture
}
func planPackages(incoming, prior Manifest, current map[string]Artifact) (PackagePlan, error) {
	plan := PackagePlan{Incoming: incoming, Installed: current}
	if err := incoming.Validate(incoming.Architecture); err != nil {
		return plan, err
	}
	familyVersion := ""
	familyCount := 0
	for name, a := range current {
		if !managedPackage(name) || a.Name != name {
			return plan, errors.New("unexpected installed package identity")
		}
		if radiusPackage(name) {
			familyCount++
			if familyVersion != "" && familyVersion != a.Version {
				return plan, errors.New("mixed installed native package family")
			}
			familyVersion = a.Version
		}
	}
	if familyCount != 0 && familyCount != 7 {
		return plan, errors.New("partial installed native package family requires explicit repair")
	}
	archives := map[string]Artifact{}
	for _, a := range prior.Artifacts {
		if !managedPackage(a.Name) || archives[a.Name].Name != "" || !regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9.+~:-]{0,95}$`).MatchString(a.Version) || !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(a.SHA256) || (a.Architecture != incoming.Architecture && (a.Name != "freeradius-common" || a.Architecture != "all")) {
			return plan, errors.New("invalid rollback artifact identity")
		}
		archives[a.Name] = a
	}
	for _, a := range incoming.Artifacts {
		old, present := current[a.Name]
		if !present {
			plan.Absent = append(plan.Absent, a.Name)
			plan.Changed = true
			continue
		}
		if samePackage(a, old) {
			continue
		}
		previous, ok := archives[a.Name]
		if !ok || !samePackage(previous, old) || prior.Schema != 1 || prior.Architecture != incoming.Architecture {
			return plan, errors.New("verified exact prior archive required before package mutation")
		}
		plan.Previous = append(plan.Previous, previous)
		plan.Changed = true
	}
	for _, name := range retiredArtifacts {
		old, present := current[name]
		if !present {
			continue
		}
		previous, ok := archives[name]
		if !ok || !samePackage(previous, old) || prior.Schema != 1 || prior.Architecture != incoming.Architecture {
			return plan, errors.New("exact cold archive required before utility retirement")
		}
		plan.Previous = append(plan.Previous, previous)
		plan.Retired = append(plan.Retired, name)
		plan.Changed = true
	}
	return plan, nil
}

// Installed state is read independently from dpkg's protected status database.
// Truncation, partial package state and mixed native families are refused.
func installedPackages() (map[string]Artifact, error) {
	f, err := rootFile("/var/lib/dpkg/status", 4<<20)
	if err != nil {
		return nil, errors.New("installed package database unavailable")
	}
	data, err := io.ReadAll(f)
	_ = f.Close()
	if err != nil {
		return nil, err
	}
	result := map[string]Artifact{}
	seen := map[string]bool{}
	for _, paragraph := range strings.Split(string(data), "\n\n") {
		fields := map[string]string{}
		for _, line := range strings.Split(paragraph, "\n") {
			if strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t") {
				continue
			}
			key, value, ok := strings.Cut(line, ": ")
			if ok {
				fields[key] = value
			}
		}
		name := fields["Package"]
		if !managedPackage(name) {
			continue
		}
		if seen[name] {
			return nil, errors.New("ambiguous installed package identity")
		}
		seen[name] = true
		switch fields["Status"] {
		case "install ok installed":
			if fields["Version"] == "" || fields["Architecture"] == "" {
				return nil, errors.New("incomplete installed package identity")
			}
			result[name] = Artifact{Name: name, Version: fields["Version"], Architecture: fields["Architecture"]}
		case "deinstall ok config-files", "purge ok not-installed":
		default:
			return nil, errors.New("package database requires explicit recovery")
		}
	}
	return result, nil
}
func verifyRollbackArtifact(ctx context.Context, a Artifact) error {
	path := filepath.Join(rollbackArtifactDirectory, a.filename())
	f, err := rootFile(path, 1<<30)
	if err != nil {
		return errors.New("prior package archive unavailable")
	}
	hash := sha256.New()
	_, err = io.Copy(hash, f)
	_ = f.Close()
	if err != nil || hex.EncodeToString(hash.Sum(nil)) != a.SHA256 {
		return errors.New("prior package checksum rejected")
	}
	metadata, err := execute(ctx, "/usr/bin/dpkg-deb", "--show", "--showformat=${Package}\t${Version}\t${Architecture}", path)
	if err != nil || string(metadata) != a.Name+"\t"+a.Version+"\t"+a.Architecture {
		return errors.New("prior package metadata rejected")
	}
	return nil
}
func validateRetiredOwner(path, name, owner string, current map[string]Artifact) error {
	if current[name].Name != name || strings.TrimSpace(owner) != name+": "+path {
		return errors.New("unmanaged or ambiguous retired utility requires explicit repair")
	}
	return nil
}

// Refuse shadow copies and unknown alternatives rather than deleting unmanaged
// files or declaring vulnerable executables retired while they remain installed.
func verifyRetiredUtilities(ctx context.Context, current map[string]Artifact) error {
	for _, directory := range []string{"/usr/bin", "/usr/local/bin"} {
		for _, entry := range []struct{ file, name string }{{"step", "step-cli"}, {"step-cli", "step-cli"}, {"step-kms-plugin", "step-kms-plugin"}} {
			path := filepath.Join(directory, entry.file)
			info, err := os.Lstat(path)
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			if err != nil {
				return err
			}
			// The official step-cli package owns /usr/bin/step-cli and registers this
			// exact update-alternatives link in postinst; dpkg does not list the alias.
			if path == "/usr/bin/step" && info.Mode()&os.ModeSymlink != 0 {
				target, err := filepath.EvalSymlinks(path)
				if err != nil || target != "/usr/bin/step-cli" || current["step-cli"].Name != "step-cli" {
					return errors.New("foreign step alternative requires explicit repair")
				}
				continue
			}
			owner, err := execute(ctx, "/usr/bin/dpkg-query", "--search", path)
			if err != nil {
				return errors.New("unmanaged retired utility requires explicit repair")
			}
			if err = validateRetiredOwner(path, entry.name, string(owner), current); err != nil {
				return err
			}
		}
	}
	return nil
}

func PreparePackages(ctx context.Context, incoming Manifest) (PackagePlan, error) {
	current, err := installedPackages()
	if err != nil {
		return PackagePlan{}, err
	}
	if err = verifyRetiredUtilities(ctx, current); err != nil {
		return PackagePlan{}, err
	}
	var prior Manifest
	f, err := rootFile(rollbackArtifactDirectory+"/manifest.json", 65536)
	if err == nil {
		decoder := json.NewDecoder(f)
		decoder.DisallowUnknownFields()
		err = decoder.Decode(&prior)
		var extra any
		if err == nil && decoder.Decode(&extra) != io.EOF {
			err = errors.New("trailing rollback manifest data")
		}
		_ = f.Close()
	} else if errors.Is(err, os.ErrNotExist) {
		err = nil
	}
	if err != nil {
		return PackagePlan{}, errors.New("protected rollback manifest unavailable")
	}
	plan, err := planPackages(incoming, prior, current)
	if err != nil {
		return plan, err
	}
	for _, a := range plan.Previous {
		if err = verifyRollbackArtifact(ctx, a); err != nil {
			return plan, err
		}
	}
	return plan, nil
}

// install applies only the journaled plan; retired utilities are never forward artifacts.
func (p PackagePlan) install(ctx context.Context) error {
	if err := InstallArtifacts(ctx, p.Incoming); err != nil {
		return err
	}
	if len(p.Retired) == 0 {
		return nil
	}
	return withPackagePolicy(ctx, func() error {
		args := append([]string{"--remove"}, p.Retired...)
		if _, err := execute(ctx, "/usr/bin/dpkg", args...); err != nil {
			return err
		}
		actual, err := installedPackages()
		if err != nil {
			return err
		}
		for _, name := range p.Retired {
			if _, present := actual[name]; present {
				return errors.New("retired utility remains installed")
			}
		}
		return verifyRetiredUtilities(ctx, actual)
	})
}

func (p PackagePlan) Rollback(ctx context.Context) error {
	// Reverify immutable local bytes immediately before use; never fetch packages.
	for _, a := range p.Previous {
		if err := verifyRollbackArtifact(ctx, a); err != nil {
			return err
		}
	}
	return withPackagePolicy(ctx, func() error {
		if len(p.Previous) > 0 {
			args := []string{"--force-confold", "--install"}
			for _, a := range p.Previous {
				args = append(args, filepath.Join(rollbackArtifactDirectory, a.filename()))
			}
			if _, err := execute(ctx, "/usr/bin/dpkg", args...); err != nil {
				return err
			}
		}
		if len(p.Absent) > 0 {
			args := append([]string{"--remove"}, p.Absent...)
			if _, err := execute(ctx, "/usr/bin/dpkg", args...); err != nil {
				return err
			}
		}
		actual, err := installedPackages()
		if err != nil {
			return err
		}
		if len(actual) != len(p.Installed) {
			return errors.New("package rollback state differs")
		}
		for name, a := range p.Installed {
			if !samePackage(a, actual[name]) {
				return errors.New("package rollback identity differs")
			}
		}
		return nil
	})
}

func withPackagePolicy(ctx context.Context, operation func() error) (result error) {
	policy := File{Path: "/usr/sbin/policy-rc.d", Mode: 0755, Data: []byte("#!/bin/sh\nexit 101\n")}
	previous, err := Snapshot(policy)
	if err != nil {
		return err
	}
	if err = Write(policy); err != nil {
		return err
	}
	defer func() { result = errors.Join(result, Restore(previous)) }()
	if err = ctx.Err(); err != nil {
		return err
	}
	return operation()
}
