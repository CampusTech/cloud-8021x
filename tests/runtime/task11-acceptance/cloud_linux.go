//go:build linux

package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/adoption"
	"golang.org/x/sys/unix"
)

const cloudHelper = "/usr/local/libexec/task11-cloud-contract"
const installedAPI = control + "/original-seed/api"
const primitiveAPI = control + "/primitive-api"

// Retain the checked executable descriptor through exec; pathname substitution
// cannot change the separately pinned verifier between hashing and execution.
func cloudCall(ctx context.Context, e enrollment, args []string) ([]byte, error) {
	if err := e.Cloud.validate(); err != nil {
		return nil, err
	}
	parent, err := privateParent(cloudHelper, 0)
	if err != nil {
		return nil, err
	}
	defer func() { _ = unix.Close(parent) }()
	fd, err := unix.Openat(parent, "task11-cloud-contract", unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), "cloud-contract")
	defer func() { _ = file.Close() }()
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Uid != 0 || st.Nlink != 1 || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Mode&0022 != 0 || st.Mode&0111 == 0 {
		return nil, errors.New("unsafe pinned cloud executable")
	}
	raw, err := boundedInput(file, 256<<20)
	if err != nil || adoption.Digest(raw) != e.Cloud.HelperSHA256 {
		return nil, errors.New("cloud helper digest differs")
	}
	clear(raw)
	return runNamespaceBounded(ctx, append([]string{"/proc/self/fd/3"}, args...), nil, 8192, 30*time.Second, []*os.File{file})
}
func verifyCloud(ctx context.Context, e enrollment, expected projection, raw []byte, pin string) error {
	root, seedPin := installedAPI, e.Cloud.InstalledSeedSHA256
	if expected.Gate == "primitive-contract" {
		root, seedPin = primitiveAPI, e.Cloud.PrimitiveSeedSHA256
	}
	if adoption.Digest(raw) != pin || expected.SeedSHA256 != seedPin || expected.ApplicationSHA256 != e.ApplicationSHA256 {
		return errors.New("independent projection pin differs")
	}
	seed, err := readPrivate(root+"/seed.json", 32<<20, 0)
	if err != nil || adoption.Digest(seed) != seedPin {
		return errors.New("reviewed cloud seed changed")
	}
	clear(seed)
	actual, err := readPrivate(root+"/expected.json", 32<<20, 0)
	if err != nil || adoption.Digest(actual) != pin {
		return errors.New("fixed expected projection changed")
	}
	clear(actual)
	out, err := cloudCall(ctx, e, []string{"verify", "--gate", expected.Gate, "--application-sha256", e.ApplicationSHA256, "--expected-sha256", pin})
	if err != nil {
		return err
	}
	v, err := validateVerification(out, expected)
	if err != nil {
		return err
	}
	actual, err = readPrivate(root+"/expected.json", 32<<20, 0)
	if err != nil || adoption.Digest(actual) != pin {
		return errors.New("projection changed during verification")
	}
	clear(actual)
	return recordEvidence(evidence{Stage: "cloud-verify", Node: "outer", Operation: expected.Gate, Status: v.Phase, SHA256: v.EvidenceSHA256, Bytes: len(out)})
}
func primitiveCloudGate(ctx context.Context, e enrollment) error {
	if err := e.Cloud.validate(); err != nil {
		return err
	}
	raw, err := readPrivate(primitiveAPI+"/expected.json", 32<<20, 0)
	if err != nil {
		return err
	}
	defer clear(raw)
	var p projection
	if decodeExactJSON(raw, &p) != nil || p.Schema != 1 || p.Gate != "primitive-contract" || len(p.Records) == 0 || len(p.Commands) == 0 || len(p.Metrics) == 0 || len(p.Publications) != 2 {
		return errors.New("complete reviewed primitive projection required")
	}
	return verifyCloud(ctx, e, p, raw, e.Cloud.PrimitiveExpectedSHA256)
}
func cloudScenario(ctx context.Context, e enrollment, name, command, peer string) error {
	args := []string{"scenario", name, "--gate", "installed-traffic"}
	switch name {
	case "peer-active", "peer-passive":
		if command != "" || (peer != "10.203.11.21" && peer != "10.203.11.22") {
			return errors.New("fixed green peer required")
		}
		args = append(args, "--peer", peer)
	case "intake-unavailable", "intake-ready", "fleet-uncertain":
		if command != "" || peer != "" {
			return errors.New("intake scenario takes no target")
		}
	case "fleet-pending", "fleet-missing", "fleet-terminal":
		if command == "" || len(command) > 253 || peer != "" {
			return errors.New("actual retained command required")
		}
		args = append(args, "--command", command)
	default:
		return errors.New("unreviewed scenario refused")
	}
	raw, err := cloudCall(ctx, e, args)
	if err != nil {
		return err
	}
	if len(raw) != 0 {
		return errors.New("unexpected scenario output")
	}
	b, _ := json.Marshal(args)
	return recordEvidence(evidence{Stage: "cloud-scenario", Node: "outer", Operation: name, Status: "api-policy-only", SHA256: adoption.Digest(b)})
}

func createPrivateOnce(path string, raw []byte) error {
	parent, err := privateParent(path, 0)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(parent) }()
	fd, err := unix.Openat(parent, filepath.Base(path), unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(fd), "exclusive-evidence")
	_, err = f.Write(raw)
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	return unix.Fsync(parent)
}
