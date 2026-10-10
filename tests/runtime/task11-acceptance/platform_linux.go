//go:build linux

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/adoption"
	"github.com/CampusTech/cloud-8021x/internal/config"
	"github.com/CampusTech/cloud-8021x/internal/domain"
	"github.com/CampusTech/cloud-8021x/internal/privileged/host"
	"golang.org/x/sys/unix"
	"gopkg.in/yaml.v3"
)

type nodeProof struct {
	MachineID, Hostname, BootID, PID1, ApplicationSHA256, ConfigSHA256 string
	Namespaces                                                         map[string]string
}
type machine struct {
	Leader      int
	Root, Start string
	Proof       nodeProof
}

var hex64 = regexp.MustCompile(`^[a-f0-9]{64}$`)
var machineID = regexp.MustCompile(`^[a-f0-9]{32}$`)
var nsNames = []string{"mnt", "pid", "uts", "net", "cgroup"}

func fixtureGuard() error {
	if os.Geteuid() != 0 {
		return errors.New("fixture controller requires guest root")
	}
	return fixtureMarker()
}
func fixtureMarker() error {
	b, err := os.ReadFile(marker)
	if err != nil || strings.TrimSpace(string(b)) != "synthetic-only-v1" {
		return errors.New("owned synthetic guest marker absent")
	}
	st, err := os.Lstat(marker)
	if err != nil || !st.Mode().IsRegular() || st.Mode().Perm()&0022 != 0 {
		return errors.New("unsafe fixture marker")
	}
	var stat unix.Stat_t
	if unix.Lstat(marker, &stat) != nil || stat.Uid != 0 || stat.Nlink != 1 {
		return errors.New("unsafe fixture marker owner")
	}
	return nil
}
func loadEnrollment() (enrollment, error) {
	var e enrollment
	b, err := readPrivate(control+"/enrollment.json", 64<<10, 0)
	if err != nil {
		return e, err
	}
	if domain.DecodeJSONStrict(b, &e) != nil || e.Schema != 1 || !hex64.MatchString(e.ApplicationSHA256) || !hex64.MatchString(e.ControllerSHA256) || len(e.Nodes) != 4 {
		return e, errors.New("reviewed four-node enrollment required")
	}
	seen := map[string]bool{}
	for _, n := range nodes {
		v, ok := e.Nodes[n]
		if !ok || !machineID.MatchString(v.MachineID) || seen[v.MachineID] || v.Hostname != "task11-"+n || !hex64.MatchString(v.ConfigSHA256) || (v.Pin != "" && !hex64.MatchString(v.Pin)) {
			return e, errors.New("invalid enrolled physical node")
		}
		seen[v.MachineID] = true
	}
	if err := loadPassivePhasePins(&e, readPrivate); err != nil {
		return e, err
	}
	return e, nil
}
func readPublic(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return boundedInput(f, limit)
}
func fileDigest(path string, limit int64) (string, error) {
	b, err := readPublic(path, limit)
	if err != nil {
		return "", err
	}
	return adoption.Digest(b), nil
}
func procStart(pid int) (string, error) {
	b, err := readPublic(fmt.Sprintf("/proc/%d/stat", pid), 8192)
	if err != nil {
		return "", err
	}
	end := strings.LastIndexByte(string(b), ')')
	if end < 0 {
		return "", errors.New("invalid proc identity")
	}
	fields := strings.Fields(string(b[end+1:]))
	if len(fields) < 20 {
		return "", errors.New("short proc identity")
	}
	return fields[19], nil
}
func localProof() (nodeProof, error) {
	p := nodeProof{Namespaces: map[string]string{}}
	for path, out := range map[string]*string{"/etc/machine-id": &p.MachineID, "/etc/hostname": &p.Hostname, "/proc/sys/kernel/random/boot_id": &p.BootID, "/proc/1/comm": &p.PID1} {
		b, err := readPublic(path, 4096)
		if err != nil {
			return p, err
		}
		*out = strings.TrimSpace(string(b))
	}
	if p.PID1 != "systemd" {
		return p, errors.New("real systemd PID1 required")
	}
	for _, n := range nsNames {
		s, err := os.Readlink("/proc/self/ns/" + n)
		if err != nil {
			return p, err
		}
		p.Namespaces[n] = s
	}
	var err error
	p.ApplicationSHA256, err = fileDigest(incoming+"/cloud-8021x", 256<<20)
	if err != nil {
		return p, err
	}
	p.ConfigSHA256, err = fileDigest(incoming+"/config.yaml", config.MaxConfigBytes)
	return p, err
}

// Capture open namespace/root descriptors before execution. PID reuse cannot
// redirect nsenter after inspection; a stopped/rebooted node fails reconciliation.
func namespaceCall(ctx context.Context, m machine, args []string, input []byte, limit int, timeout time.Duration) ([]byte, error) {
	files := []*os.File{}
	defer func() {
		for _, f := range files {
			_ = f.Close()
		}
	}()
	argv := []string{"/usr/bin/nsenter"}
	flags := []string{"--mount", "--pid", "--uts", "--net", "--cgroup"}
	for i, name := range nsNames {
		f, err := os.Open(fmt.Sprintf("/proc/%d/ns/%s", m.Leader, name))
		if err != nil {
			return nil, err
		}
		files = append(files, f)
		var st unix.Stat_t
		if unix.Fstat(int(f.Fd()), &st) != nil {
			return nil, errors.New("namespace descriptor unavailable")
		}
		want, err := os.Readlink(fmt.Sprintf("/proc/%d/ns/%s", m.Leader, name))
		if err != nil || want != fmt.Sprintf("%s:[%d]", name, st.Ino) {
			return nil, errors.New("namespace changed during descriptor capture")
		}
		argv = append(argv, fmt.Sprintf("%s=/proc/self/fd/%d", flags[i], i+3))
	}
	root, err := os.Open(fmt.Sprintf("/proc/%d/root", m.Leader))
	if err != nil {
		return nil, err
	}
	files = append(files, root)
	actual, err := root.Stat()
	if err != nil {
		return nil, err
	}
	expected, err := os.Stat(m.Root)
	if err != nil || !os.SameFile(actual, expected) {
		return nil, errors.New("captured root differs")
	}
	start, err := procStart(m.Leader)
	if err != nil || start != m.Start {
		return nil, errors.New("leader changed before namespace entry")
	}
	rootArg := fmt.Sprintf("/proc/self/fd/%d", len(files)+2)
	argv = append(argv, "--root="+rootArg, "--wd="+rootArg, helper, "node")
	argv = append(argv, args...)
	return runNamespaceBounded(ctx, argv, input, limit, timeout, files)
}
func inspectMachine(ctx context.Context, n string, e enrollment) (machine, error) {
	var m machine
	if !slices.Contains(nodes, n) {
		return m, errors.New("unknown machine")
	}
	out, err := runBounded(ctx, []string{"/usr/bin/machinectl", "show", "task11-" + n, "--property=Name", "--property=Leader", "--property=RootDirectory", "--property=Class"}, nil, 8192, 15*time.Second)
	if err != nil {
		return m, err
	}
	props := map[string]string{}
	for _, line := range strings.Split(string(out), "\n") {
		k, v, ok := strings.Cut(line, "=")
		if ok {
			props[k] = v
		}
	}
	m.Leader, err = strconv.Atoi(props["Leader"])
	if err != nil || m.Leader < 2 || props["Name"] != "task11-"+n || props["Class"] != "container" {
		return m, errors.New("registered nspawn machine identity required")
	}
	m.Root = "/var/lib/cloud8021x-task11/roots/task11-" + n
	if props["RootDirectory"] != m.Root {
		return m, errors.New("machine root differs from fixed enrollment")
	}
	parent, err := privateParent(m.Root+"/check", 0)
	if err != nil {
		return m, err
	}
	_ = unix.Close(parent)
	expected, err := os.Stat(m.Root)
	if err != nil {
		return m, err
	}
	actual, err := os.Stat(fmt.Sprintf("/proc/%d/root", m.Leader))
	if err != nil || !os.SameFile(expected, actual) {
		return m, errors.New("registered leader has a different root")
	}
	m.Start, err = procStart(m.Leader)
	if err != nil {
		return m, err
	}
	digest, err := fileDigest(m.Root+helper, 256<<20)
	if err != nil || digest != e.ControllerSHA256 {
		return m, errors.New("guest controller digest differs")
	}
	out, err = namespaceCall(ctx, m, []string{"probe"}, nil, 8192, 15*time.Second)
	if err != nil {
		return m, err
	}
	if domain.DecodeJSONStrict(out, &m.Proof) != nil {
		return m, errors.New("invalid node proof")
	}
	want := e.Nodes[n]
	if m.Proof.MachineID != want.MachineID || m.Proof.Hostname != want.Hostname || m.Proof.PID1 != "systemd" || m.Proof.BootID == "" || m.Proof.ApplicationSHA256 != e.ApplicationSHA256 || m.Proof.ConfigSHA256 != want.ConfigSHA256 {
		return m, errors.New("node identity or staged release/config differs")
	}
	for _, name := range nsNames {
		actual, err := os.Readlink(fmt.Sprintf("/proc/%d/ns/%s", m.Leader, name))
		if err != nil {
			return m, err
		}
		outer, err := os.Readlink("/proc/self/ns/" + name)
		if err != nil {
			return m, err
		}
		if m.Proof.Namespaces[name] != actual || actual == outer {
			return m, errors.New("node namespace isolation differs")
		}
	}
	after, err := procStart(m.Leader)
	if err != nil || after != m.Start {
		return m, errors.New("leader changed during enrollment check")
	}
	return m, nil
}
func nodeCall(ctx context.Context, n string, e enrollment, args []string, input []byte, limit int, timeout time.Duration) ([]byte, error) {
	m, err := inspectMachine(ctx, n, e)
	if err != nil {
		return nil, err
	}
	out, err := namespaceCall(ctx, m, args, input, limit, timeout)
	after, checkErr := inspectMachine(ctx, n, e)
	if checkErr != nil || after.Leader != m.Leader || after.Start != m.Start || after.Proof.BootID != m.Proof.BootID {
		return nil, errors.New("node rebooted or changed during operation; reconcile actual state")
	}
	return out, err
}
func nodeConfig() (config.Config, host.Manifest, error) {
	var manifest host.Manifest
	b, err := readPrivate(incoming+"/config.yaml", config.MaxConfigBytes, 0)
	if err != nil {
		return config.Config{}, manifest, err
	}
	c, err := config.Decode(bytes.NewReader(b))
	if err != nil {
		return c, manifest, err
	}
	raw, err := readPrivate(incoming+"/manifest.json", 1<<20, 0)
	if err != nil {
		return c, manifest, err
	}
	if domain.DecodeJSONStrict(raw, &manifest) != nil || manifest.ConfigSHA256 != adoption.Digest(b) {
		return c, manifest, errors.New("staged manifest configuration differs")
	}
	return c, manifest, nil
}
func nodeCommand(ctx context.Context, args []string, in io.Reader, out io.Writer) error {
	if err := fixtureGuard(); err != nil {
		return err
	}
	if handled, err := dispatchScenarioProbe(ctx, args, in, out, nodeScenarioProbe); handled {
		return err
	}
	switch args[0] {
	case "scenario-accounting", "scenario-ca":
		if len(args) != 1 {
			return errors.New("fixed scenario reader accepts private typed input only")
		}
		return nodeScenarioRead(ctx, args[0], in, out)
	case "passive-install", "passive-observe":
		if len(args) != 1 {
			return errors.New("fixed passive action accepts private typed input only")
		}
		raw, err := boundedInput(in, 16<<10)
		if err != nil {
			return err
		}
		defer clear(raw)
		if args[0] == "passive-install" {
			return installPassiveNode(raw, out)
		}
		return nodePassiveObserver(ctx, raw, out)
	case "inventory-publication":
		if len(args) != 1 {
			return errors.New("fixed publication observation takes no arguments")
		}
		return observePublication(out)

	case "active-proof":
		if len(args) != 1 {
			return errors.New("fixed active proof arguments required")
		}
		for _, unit := range []string{"cloud-8021x.service", "freeradius.service", "step-ca.service", "step-ca-rsa.service", "datadog-agent.service", "datadog-agent-ddot.service"} {
			if _, err := runBounded(ctx, []string{"/usr/bin/systemctl", "is-active", "--quiet", unit}, nil, 4096, 10*time.Second); err != nil {
				return errors.New("actual active service proof absent")
			}
		}
		return writeSQLObservation(ctx, false, out)
	case "recover":
		if len(args) != 1 {
			return errors.New("recovery accepts only a private typed request")
		}
		raw, err := boundedInput(in, 8192)
		if err != nil {
			return err
		}
		var request recoveryRequest
		if domain.DecodeJSONStrict(raw, &request) != nil {
			return errors.New("invalid closed recovery request")
		}
		argv, err := recoveryCommand(request)
		if err != nil {
			return err
		}
		digest, err := fileDigest(argv[0], 256<<20)
		if err != nil || digest != request.ApplicationSHA256 {
			return errors.New("installed recovery release differs")
		}
		result, err := runBounded(ctx, argv, nil, 8192, 2*time.Minute)
		if err != nil {
			return err
		}
		_, err = out.Write(result)
		return err
	case "sql-observe", "sql-project":
		if len(args) != 1 {
			return errors.New("fixed SQL projection arguments required")
		}
		return writeSQLObservation(ctx, args[0] == "sql-project", out)
	case "probe":
		if len(args) != 1 {
			return errors.New("probe arguments refused")
		}
		p, err := localProof()
		if err != nil {
			return err
		}
		return json.NewEncoder(out).Encode(p)
	case "config":
		if len(args) != 1 {
			return errors.New("config arguments refused")
		}
		c, _, err := nodeConfig()
		if err != nil {
			return err
		}
		return json.NewEncoder(out).Encode(c)
	case "read", "write":
		if len(args) != 4 || !hex64.MatchString(args[3]) {
			return errors.New("fixed slot and digest required")
		}
		src, dst, err := receiptPaths(args[1], args[2])
		if err != nil {
			return err
		}
		c, m, err := nodeConfig()
		if err != nil {
			return err
		}
		var raw []byte
		if args[0] == "read" {
			raw, err = readPrivate(src, adoption.MaxBytes, 0)
		} else {
			raw, err = boundedInput(in, adoption.MaxBytes)
		}
		if err != nil {
			return err
		}
		if adoption.Digest(raw) != args[3] {
			return errors.New("private transfer digest differs")
		}
		if err = verifyReceipt(args[1], args[2], raw, c, m.ApplicationSHA256, time.Now().UTC()); err != nil {
			return err
		}
		if args[0] == "read" {
			_, err = out.Write(raw)
			return err
		}
		if err = atomicPrivate(dst, raw, 0); err != nil {
			return err
		}
		return json.NewEncoder(out).Encode(map[string]string{"sha256": adoption.Digest(raw)})
	case "receipt-digest":
		if len(args) != 3 {
			return errors.New("fixed receipt slot required")
		}
		src, _, err := receiptPaths(args[1], args[2])
		if err != nil {
			return err
		}
		raw, err := readPrivate(src, adoption.MaxBytes, 0)
		if err != nil {
			return err
		}
		return json.NewEncoder(out).Encode(map[string]string{"sha256": adoption.Digest(raw)})
	case "op":
		if len(args) != 3 || !hex64.MatchString(args[2]) {
			return errors.New("pinned CLI operation required")
		}
		argv, err := shippingCommand(args[1])
		if err != nil {
			return err
		}
		got, err := fileDigest(argv[0], 256<<20)
		if err != nil || got != args[2] {
			return errors.New("shipping executable differs")
		}
		if args[1] == "capture" {
			if err = verifyRootSourceProvenance(); err != nil {
				return err
			}
			for _, unit := range []string{"freeradius.service", "step-ca.service", "step-ca-rsa.service"} {
				if _, err = runBounded(ctx, []string{"/usr/bin/systemctl", "is-active", "--quiet", unit}, nil, 4096, 15*time.Second); err != nil {
					return errors.New("genuine source native/CA service is not active")
				}
			}
		}
		raw, err := runBounded(ctx, argv, nil, 1<<20, 20*time.Minute)
		if err != nil {
			return err
		}
		_, err = out.Write(raw)
		return err
	case "pin-config":
		if len(args) != 1 {
			return errors.New("pin arguments refused")
		}
		var pins map[string]string
		b, err := boundedInput(in, 8192)
		if err != nil || domain.DecodeJSONStrict(b, &pins) != nil || len(pins) != 4 {
			return errors.New("four source-key results required")
		}
		c, m, err := nodeConfig()
		if err != nil {
			return err
		}
		c.Deployment.SourcePrimaryKey = pins["blue-primary"]
		c.Deployment.SourceSecondaryKey = pins["blue-secondary"]
		c.Deployment.DestinationPrimaryKey = pins["green-primary"]
		c.Deployment.DestinationSecondaryKey = pins["green-secondary"]
		if err = c.ValidateHandoffPins(); err != nil {
			return err
		}
		b, err = yaml.Marshal(c)
		if err != nil {
			return err
		}
		m.ConfigSHA256 = adoption.Digest(b)
		mb, err := json.Marshal(m)
		if err != nil {
			return err
		}
		// A crash between the two atomic writes intentionally leaves a mismatched
		// manifest and fails closed. Re-run only after operator review of the pins.
		if err = atomicPrivate(incoming+"/config.yaml", b, 0); err != nil {
			return err
		}
		if err = atomicPrivate(incoming+"/manifest.json", mb, 0); err != nil {
			return err
		}
		return json.NewEncoder(out).Encode(map[string]string{"config_sha256": m.ConfigSHA256})
	}
	return errors.New("unknown private node action")
}
