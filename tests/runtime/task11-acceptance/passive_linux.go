//go:build linux

package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/adoption"
	"github.com/CampusTech/cloud-8021x/internal/domain"
	"github.com/CampusTech/cloud-8021x/internal/privileged/host"
	audit "github.com/CampusTech/cloud-8021x/tests/runtime/task11-passive-audit/contract"
	"golang.org/x/sys/unix"
)

type passiveInstall struct {
	Phase, ApplicationSHA256 string
	Manifest                 audit.Manifest
}
type publication struct {
	Bytes        []byte
	Installation string
}
type retainedPassiveWindow struct {
	Label, File string
	Baselines   map[string]passiveWindow
}

func originalInputs(e enrollment) (map[string][]byte, error) {
	if err := e.Passive.validate(); err != nil {
		return nil, err
	}
	raw, err := readPrivate(control+"/original-seed/original-manifest.json", 16<<10, 0)
	if err != nil {
		return nil, err
	}
	var m originalManifest
	if adoption.Digest(raw) != e.Passive.OriginalSeedSHA256 || decodeExactJSON(raw, &m) != nil || m.Schema != 1 || len(m.Files) != len(originalNames) {
		return nil, errors.New("reviewed original source manifest differs")
	}
	files := map[string][]byte{}
	budget := 48 << 20
	for _, name := range originalNames {
		v, er := readPrivate(control+"/original-seed/"+name, 32<<20, 0)
		if er != nil {
			clearInputs(files)
			return nil, er
		}
		budget -= len(v)
		if budget < 0 || adoption.Digest(v) != m.Files[name] {
			clear(v)
			clearInputs(files)
			return nil, errors.New("original preserved input changed")
		}
		files[name] = v
	}
	if adoption.Digest(files["api/seed.json"]) != e.Cloud.InstalledSeedSHA256 || adoption.Digest(files["source/var/lib/cloud-8021x/certificate-state.json"]) != e.Cloud.OriginalStateSHA256 {
		clearInputs(files)
		return nil, errors.New("independent original/cloud pins differ")
	}
	return files, nil
}
func clearInputs(files map[string][]byte) {
	for _, v := range files {
		clear(v)
	}
}
func expectedPreparedManifest(ctx context.Context, e enrollment, node string) (audit.Manifest, error) {
	var empty audit.Manifest
	files, err := originalInputs(e)
	if err != nil {
		return empty, err
	}
	defer clearInputs(files)
	c, err := remoteConfig(ctx, node, e)
	if err != nil {
		return empty, err
	}
	source := strings.Replace(node, "green-", "blue-", 1)
	raw, err := nodeCall(ctx, source, e, []string{"receipt-digest", "parallel", roleOf(node)}, nil, 8192, 15*time.Second)
	if err != nil {
		return empty, err
	}
	pin, err := publicResult(raw, "sha256")
	if err != nil {
		return empty, err
	}
	envelope, err := nodeCall(ctx, source, e, []string{"read", "parallel", roleOf(node), pin}, nil, adoption.MaxBytes, 30*time.Second)
	if err != nil {
		return empty, err
	}
	defer clear(envelope)
	binding, err := adoption.ExpectedBinding(c, e.ApplicationSHA256)
	if err != nil {
		return empty, err
	}
	public, err := hex.DecodeString(e.Nodes[source].Pin)
	if err != nil {
		return empty, err
	}
	authorization, err := adoption.Verify(envelope, ed25519.PublicKey(public), binding, time.Now().UTC())
	if err != nil {
		return empty, err
	}
	return derivePassiveManifest(c, authorization, files, e.Passive.OriginalSeedSHA256, c.Database.InstanceCAPEMSHA256, time.Now().UTC())
}
func manifestKey(node, phase string) (string, error) {
	if _, err := greenPeer(node); err != nil {
		return "", err
	}
	if phase != "prepared" && phase != "deactivated" {
		return "", errors.New("unknown passive phase")
	}
	return node + "-" + phase, nil
}
func savePassiveManifest(ctx context.Context, e *enrollment, node, phase string, m audit.Manifest) error {
	key, err := manifestKey(node, phase)
	if err != nil {
		return err
	}
	if audit.ValidateManifest(m, audit.Request{OriginalSeedSHA256: e.Passive.OriginalSeedSHA256}) != nil {
		return errors.New("independent passive manifest invalid")
	}
	raw, err := json.Marshal(m)
	if err != nil {
		return err
	}
	pin := adoption.Digest(raw)
	if old := e.Passive.Manifests[key]; old != "" && old != pin {
		return errors.New("previously frozen passive phase manifest differs")
	}
	input, err := json.Marshal(passiveInstall{phase, e.ApplicationSHA256, m})
	if err != nil {
		return err
	}
	ack, err := nodeCall(ctx, node, *e, []string{"passive-install"}, input, 8192, 20*time.Second)
	if err != nil {
		return err
	}
	got, err := publicResult(ack, "sha256")
	if err != nil || got != pin {
		return errors.New("installed independent passive manifest differs")
	}
	if err = atomicPrivate(control+"/passive-"+key+".json", raw, 0); err != nil {
		return err
	}
	if e.Passive.Manifests == nil {
		e.Passive.Manifests = map[string]string{}
	}
	e.Passive.Manifests[key] = pin
	state, err := json.Marshal(e)
	if err != nil {
		return err
	}
	return atomicPrivate(control+"/enrollment.json", state, 0)
}
func loadPassiveManifest(e enrollment, node, phase string) (audit.Manifest, error) {
	var m audit.Manifest
	key, err := manifestKey(node, phase)
	if err != nil {
		return m, err
	}
	raw, err := readPrivate(control+"/passive-"+key+".json", audit.MaxRequestBytes, 0)
	if err != nil {
		return m, err
	}
	if !validSHA(e.Passive.Manifests[key]) || adoption.Digest(raw) != e.Passive.Manifests[key] || decodeExactJSON(raw, &m) != nil || audit.ValidateManifest(m, audit.Request{OriginalSeedSHA256: e.Passive.OriginalSeedSHA256}) != nil {
		return m, errors.New("previous independent phase manifest unavailable")
	}
	return m, nil
}
func installPassiveNode(input []byte, out interface{ Write([]byte) (int, error) }) error {
	var r passiveInstall
	if decodeExactJSON(input, &r) != nil || !validSHA(r.ApplicationSHA256) || (r.Phase != "prepared" && r.Phase != "deactivated") || audit.ValidateManifest(r.Manifest, audit.Request{OriginalSeedSHA256: r.Manifest.OriginalSeedSHA256}) != nil {
		return errors.New("invalid fixed passive seed request")
	}
	c, manifest, err := nodeConfig()
	if err != nil || manifest.ApplicationSHA256 != r.ApplicationSHA256 {
		return errors.New("passive seed installed release differs")
	}
	known, err := host.KnownInstallation()
	if err != nil || !known {
		return errors.New("real completed preparation required")
	}
	receipt, trust, err := host.ParallelInstalledReceipt(c, r.ApplicationSHA256)
	if err != nil || receipt == "" || trust != r.Manifest.Slots["client-trust"] {
		return errors.New("actual prepared generation differs")
	}
	prior, err := readPrivate(audit.SeedManifest, audit.MaxRequestBytes, 0)
	if err == nil {
		var old audit.Manifest
		if decodeExactJSON(prior, &old) != nil {
			return errors.New("prior passive manifest invalid")
		}
		copy := r.Manifest
		copy.Slots = map[string]string{}
		for k, v := range r.Manifest.Slots {
			copy.Slots[k] = v
		}
		if r.Phase == "deactivated" {
			copy.Slots["inventory"] = old.Slots["inventory"]
		}
		a, _ := json.Marshal(copy)
		b, _ := json.Marshal(old)
		if !bytes.Equal(a, b) {
			return errors.New("passive phase attempted to replace original material")
		}
	} else if !errors.Is(err, os.ErrNotExist) || r.Phase != "prepared" {
		return errors.New("original prepared passive manifest required")
	}
	raw, err := json.Marshal(r.Manifest)
	if err != nil {
		return err
	}
	if err = atomicPrivate(audit.SeedManifest, raw, 0); err != nil {
		return err
	}
	return json.NewEncoder(out).Encode(map[string]string{"sha256": adoption.Digest(raw)})
}
func observePublication(out interface{ Write([]byte) (int, error) }) error {
	c, m, err := nodeConfig()
	if err != nil {
		return err
	}
	known, err := host.KnownInstallation()
	if err != nil || !known {
		return errors.New("completed publication installation required")
	}
	receipt, _, err := host.ParallelInstalledReceipt(c, m.ApplicationSHA256)
	if err != nil || receipt == "" {
		return errors.New("completed publication generation unavailable")
	}
	accounts, err := host.ReadAccounts()
	if err != nil {
		return err
	}
	raw, err := readPublishedSnapshot(c.Paths.InventoryFile, accounts.RuntimeUID)
	if err != nil {
		return err
	}
	defer clear(raw)
	if _, err = domain.DecodeSnapshot(bytes.NewReader(raw)); err != nil {
		return err
	}
	return json.NewEncoder(out).Encode(publication{raw, receipt})
}
func nodePassiveObserver(ctx context.Context, input []byte, out interface{ Write([]byte) (int, error) }) error {
	var r audit.Request
	if decodeExactJSON(input, &r) != nil || audit.ValidateRequest(r) != nil {
		return errors.New("invalid fixed observer request")
	}
	parent, err := privateParent(audit.Executable, 0)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(parent) }()
	fd, err := unix.Openat(parent, filepath.Base(audit.Executable), unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(fd), "fixed-passive-observer")
	defer func() { _ = f.Close() }()
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Uid != 0 || st.Gid != 0 || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Mode&0777 != 0755 || st.Nlink != 1 {
		return errors.New("unsafe fixed observer executable")
	}
	binary, err := boundedInput(f, 256<<20)
	if err != nil || adoption.Digest(binary) != r.ObserverSHA256 {
		clear(binary)
		return errors.New("reviewed observer executable differs")
	}
	clear(binary)
	result, err := runBoundedFiles(ctx, []string{"/proc/self/fd/3", "observe"}, input, audit.MaxResultBytes, 55*time.Second, []*os.File{f})
	if err != nil {
		return err
	}
	defer clear(result)
	_, err = out.Write(result)
	return err
}
func collectPassive(ctx context.Context, e enrollment, node, phase string) (audit.Result, error) {
	var empty audit.Result
	if err := e.Passive.validate(); err != nil {
		return empty, err
	}
	inputs, err := originalInputs(e)
	if err != nil {
		return empty, err
	}
	clearInputs(inputs)
	m, err := loadPassiveManifest(e, node, phase)
	if err != nil {
		return empty, err
	}
	machine, err := inspectMachine(ctx, node, e)
	if err != nil {
		return empty, err
	}
	key, _ := manifestKey(node, phase)
	r := audit.Request{Schema: 1, Node: node, Phase: phase, MachineID: e.Nodes[node].MachineID, Pin: e.Nodes[node].Pin, BootID: machine.Proof.BootID, Namespaces: machine.Proof.Namespaces, ApplicationSHA256: e.ApplicationSHA256, ApplicationSourceSHA: e.Passive.ApplicationSourceSHA, ConfigSHA256: e.Nodes[node].ConfigSHA256, ControllerSHA256: e.ControllerSHA256, ObserverSHA256: e.Passive.ObserverSHA256, SeedSHA256: e.Passive.Manifests[key], OriginalSeedSHA256: e.Passive.OriginalSeedSHA256}
	input, err := json.Marshal(r)
	if err != nil {
		return empty, err
	}
	started := time.Now().UTC()
	raw, err := namespaceCall(ctx, machine, []string{"passive-observe"}, input, audit.MaxResultBytes, 65*time.Second)
	if err != nil {
		return empty, err
	}
	after, err := inspectMachine(ctx, node, e)
	if err != nil || after.Leader != machine.Leader || after.Start != machine.Start || after.Proof.BootID != machine.Proof.BootID {
		return empty, errors.New("node changed during independent observation")
	}
	c, err := remoteConfig(ctx, node, e)
	if err != nil {
		return empty, err
	}
	result, err := validatePassiveResult(raw, input, r, m, c, started)
	if err != nil {
		return empty, err
	}
	for _, p := range result.SQL.Prepared {
		n := "green" + strings.TrimPrefix(p.Role, "radius")
		binding, er := remoteConfig(ctx, n, e)
		if er != nil {
			return empty, er
		}
		b, er := adoption.ExpectedBinding(binding, e.ApplicationSHA256)
		if er != nil || b.ConfigSHA256 != p.ConfigSHA256 {
			return empty, errors.New("prepared peer config differs")
		}
	}
	path := fmt.Sprintf("%s/passive-result-%s-%s-%d.json", control, node, phase, time.Now().UnixNano())
	if err = createPrivateOnce(path, raw); err != nil {
		return empty, err
	}
	return result, recordEvidence(evidence{Stage: "passive-audit", Node: node, Operation: phase, Status: "actual-observer-output", SHA256: adoption.Digest(raw), Bytes: len(raw)})
}
func startPassiveWindow(ctx context.Context, e enrollment, label string) (retainedPassiveWindow, error) {
	w := retainedPassiveWindow{Label: label, Baselines: map[string]passiveWindow{}}
	for _, node := range []string{"green-primary", "green-secondary"} {
		peer, _ := greenPeer(node)
		raw, err := cloudCall(ctx, e, []string{"passive-audit", "baseline", "--seed-sha256", e.Cloud.InstalledSeedSHA256, "--peer", peer})
		if err != nil {
			return w, err
		}
		b, err := validatePassiveWindow(raw, e.Cloud.InstalledSeedSHA256, node, nil)
		if err != nil {
			return w, err
		}
		w.Baselines[node] = b
	}
	w.File = fmt.Sprintf("%s/passive-window-%s-%d.json", control, label, time.Now().UnixNano())
	raw, err := json.Marshal(w)
	if err != nil {
		return w, err
	}
	return w, createPrivateOnce(w.File, raw)
}
func finishPassiveWindow(ctx context.Context, e enrollment, w retainedPassiveWindow) error {
	saved, err := readPrivate(w.File, 16<<10, 0)
	if err != nil {
		return err
	}
	expected, _ := json.Marshal(w)
	if !bytes.Equal(saved, expected) {
		return errors.New("retained before-operation API baseline changed")
	}
	results := map[string]passiveWindow{}
	for _, node := range []string{"green-primary", "green-secondary"} {
		b, ok := w.Baselines[node]
		if !ok {
			return errors.New("missing retained peer baseline")
		}
		peer, _ := greenPeer(node)
		raw, er := cloudCall(ctx, e, []string{"passive-audit", "final", "--seed-sha256", e.Cloud.InstalledSeedSHA256, "--peer", peer, "--after-sequence", strconv.Itoa(b.ToSequence), "--baseline-sha256", b.BaselineSHA256})
		if er != nil {
			return er
		}
		v, er := validatePassiveWindow(raw, e.Cloud.InstalledSeedSHA256, node, &b)
		if er != nil {
			return er
		}
		results[node] = v
	}
	raw, err := json.Marshal(results)
	if err != nil {
		return err
	}
	if err = createPrivateOnce(w.File+".final", raw); err != nil {
		return err
	}
	return recordEvidence(evidence{Stage: "passive-api", Node: "green-pair", Operation: w.Label, Status: "actual-retained-window-verified", SHA256: adoption.Digest(raw), Bytes: len(raw)})
}

func freezeDeactivatedManifests(ctx context.Context, e *enrollment) error {
	files, err := originalInputs(*e)
	if err != nil {
		return err
	}
	defer clearInputs(files)
	for _, node := range []string{"green-primary", "green-secondary"} {
		m, er := loadPassiveManifest(*e, node, "prepared")
		if er != nil {
			return er
		}
		raw, er := nodeCall(ctx, node, *e, []string{"inventory-publication"}, nil, 24<<20, 20*time.Second)
		if er != nil {
			return er
		}
		var p publication
		if decodeExactJSON(raw, &p) != nil || len(p.Bytes) > domain.MaxSnapshotBytes || !machineID.MatchString(p.Installation) {
			clear(raw)
			return errors.New("actual owned publication generation unavailable")
		}
		clear(raw)
		cfg, er := remoteConfig(ctx, node, *e)
		if er != nil {
			clear(p.Bytes)
			return er
		}
		hash, er := deactivatedInventory(cfg, files["source/etc/freeradius/3.0/device-policy-cache.json"], p.Bytes, files["api/seed.json"])
		clear(p.Bytes)
		if er != nil {
			return er
		}
		m.Slots["inventory"] = hash
		if er = savePassiveManifest(ctx, e, node, "deactivated", m); er != nil {
			return er
		}
	}
	return nil
}
func rebootEnrolled(ctx context.Context, e enrollment, node string, before audit.Result) (machine, error) {
	var empty machine
	current, err := inspectMachine(ctx, node, e)
	if err != nil {
		return empty, err
	}
	if current.Proof.BootID != before.Identity.BootID || current.Proof.MachineID != before.Identity.MachineID {
		return empty, errors.New("node changed before genuine reboot")
	}
	fd, err := unix.PidfdOpen(current.Leader, 0)
	if err != nil {
		return empty, errors.New("kernel old-Leader identity unavailable")
	}
	defer func() { _ = unix.Close(fd) }()
	start, err := procStart(current.Leader)
	if err != nil || start != current.Start {
		return empty, errors.New("old Leader changed before reboot")
	}
	if err = recordEvidence(evidence{Stage: "passive-reboot", Node: node, Operation: "machinectl-reboot", Status: "requesting-real-enrolled-reboot"}); err != nil {
		return empty, err
	}
	rebootCtx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	if _, err = runNamespaceBounded(rebootCtx, []string{"/usr/bin/machinectl", "reboot", "task11-" + node}, nil, 8192, 20*time.Second, nil); err != nil {
		return empty, errors.New("reboot request uncertain; reconcile enrolled machine")
	}
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-rebootCtx.Done():
			return empty, errors.New("genuine enrolled reboot not proven; retain prior side effects")
		case <-ticker.C:
			p := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
			if _, er := unix.Poll(p, 0); er != nil {
				return empty, er
			}
			if p[0].Revents&unix.POLLIN == 0 {
				continue
			}
			after, er := inspectMachine(rebootCtx, node, e)
			if er != nil {
				continue
			}
			if after.Proof.BootID == current.Proof.BootID {
				continue
			}
			if after.Root != current.Root || after.Proof.MachineID != current.Proof.MachineID || after.Proof.Hostname != current.Proof.Hostname {
				return empty, errors.New("reboot changed enrolled physical identity")
			}
			return after, nil
		}
	}
}
func passivePair(ctx context.Context, e enrollment, phase string, reboot bool) error {
	// This is actual execution only: the helper runs in pinned namespaces, every
	// reboot is requested from machinectl, and the old Leader must retire via pidfd.
	for _, node := range []string{"green-primary", "green-secondary"} {
		before, err := collectPassive(ctx, e, node, phase)
		if err != nil {
			return err
		}
		if !reboot {
			continue
		}
		machine, err := rebootEnrolled(ctx, e, node, before)
		if err != nil {
			return err
		}
		after, err := collectPassive(ctx, e, node, phase)
		if err != nil {
			return err
		}
		if after.Identity.BootID != machine.Proof.BootID {
			return errors.New("node changed after observed reboot")
		}
		if err = comparePassiveBoot(before, after); err != nil {
			return err
		}
		if err = recordEvidence(evidence{Stage: "passive-reboot", Node: node, Operation: phase, Status: "actual-old-leader-retired-new-boot-preserved"}); err != nil {
			return err
		}
	}
	return nil
}
func installedPassiveAudit(ctx context.Context, e enrollment) error {
	w, err := startPassiveWindow(ctx, e, "prepared-reboot")
	if err != nil {
		return err
	}
	if err = passivePair(ctx, e, "prepared", true); err != nil {
		return err
	}
	return finishPassiveWindow(ctx, e, w)
}
