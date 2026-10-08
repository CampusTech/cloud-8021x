package host

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/CampusTech/cloud-8021x/internal/domain"
	"github.com/CampusTech/cloud-8021x/internal/templates/systemd"
	"golang.org/x/sys/unix"
)

var daemonWorkerUnits = []string{"cloud-8021x-sources.timer", "cloud-8021x-renew.timer", "cloud-8021x-sources.service", "cloud-8021x-renew.service", "cloud-8021x.service"}

type workerFence struct {
	Attempt                              int64
	Version                              int
	Transition, Node, ConfigSHA256       string
	Helper                               writerPID
	Native                               writerPID
	NativeGeneration, NativeModuleSHA256 string
	Processes                            []writerPID
	Units                                []SavedFile
}

func daemonProcessEvidence(processes []writerProcess, exclude int) []writerPID {
	selected := map[int]bool{}
	for _, p := range processes {
		args := strings.Split(p.Args, "\x00")
		if p.PID != exclude && len(args) > 0 && filepath.Base(args[0]) == "cloud-8021x" {
			selected[p.PID] = true
		}
	}
	for changed := true; changed; {
		changed = false
		for _, p := range processes {
			if p.PID != exclude && selected[p.Parent] && !selected[p.PID] {
				selected[p.PID] = true
				changed = true
			}
		}
	}
	out := []writerPID{}
	for _, p := range processes {
		if selected[p.PID] {
			out = append(out, writerPID{p.PID, p.Start})
		}
	}
	return out
}
func loadWorkerFence(id, node, hash string, attempt int64) (workerFence, []byte, error) {
	var r workerFence
	dir, e := writerReceiptDirectory(id)
	if e != nil {
		return r, nil, e
	}
	raw, e := readPrivateCache(filepath.Join(dir, "worker-original.json"), 1<<20)
	if e != nil {
		return r, nil, e
	}
	if domain.DecodeJSONStrict(raw, &r) != nil || r.Version != 1 || r.Attempt <= 0 || (attempt > 0 && r.Attempt != attempt) || r.Transition != id || r.Node != node || r.ConfigSHA256 != hash || r.Helper.Start == 0 || r.Helper.PID <= 0 || len(r.Processes) > 4096 || len(r.Units) != len(daemonWorkerUnits) {
		return r, nil, errors.New("worker fence identity differs")
	}
	canonical, _ := json.Marshal(r)
	if !bytes.Equal(raw, canonical) {
		return r, nil, errors.New("worker original receipt is not canonical")
	}
	expected, e := systemd.Render()
	if e != nil {
		return r, nil, e
	}
	for i, saved := range r.Units {
		path := "/etc/systemd/system/" + daemonWorkerUnits[i]
		if saved.Path != path || !saved.Exists || saved.UID != 0 || saved.GID != 0 || saved.Mode != 0644 || !bytes.Equal(saved.Data, expected[path]) {
			return r, nil, errors.New("worker original unit is not exact protected unit")
		}
	}
	return r, raw, nil
}
func validateWorkerUnits(r workerFence, complete bool) error {
	for _, saved := range r.Units {
		parent, e := parentDescriptor(saved.Path, 0, false)
		if e != nil {
			return e
		}
		_ = unix.Close(parent)
		target, e := os.Readlink(saved.Path)
		if e == nil {
			if target != "/dev/null" {
				return errors.New("unknown worker unit mask")
			}
			continue
		}
		if complete {
			return errors.New("worker persistent mask absent")
		}
		now, e := Snapshot(File{Path: saved.Path})
		if e != nil || !now.Exists || now.UID != 0 || now.GID != 0 || now.Mode != saved.Mode || !bytes.Equal(now.Data, saved.Data) {
			return errors.New("worker unit differs from original or fixed mask")
		}
	}
	return nil
}
func workerProcessesGone(r workerFence) error {
	processes, e := scanWriterProcesses()
	if e != nil {
		return e
	}
	if len(daemonProcessEvidence(processes, os.Getpid())) != 0 {
		return errors.New("daemon/helper processes still active")
	}
	for _, p := range processes {
		if slices.Contains(r.Processes, writerPID{p.PID, p.Start}) {
			return errors.New("observed Go worker descendant still active")
		}
	}
	return nil
}
func verifyWorkerFence(ctx context.Context, r workerFence, b *RadiusBackend) error {
	if e := validateWorkerUnits(r, true); e != nil {
		return e
	}
	if e := writerUnitsQuiescent(ctx, b.command, daemonWorkerUnits); e != nil {
		return e
	}
	active, e := b.Running(ctx)
	if e != nil || active {
		return errors.New("native not quiescent for cold rollback")
	}
	uid, _, e := identity("freerad")
	if e != nil {
		return e
	}
	if e = proveNativeProcessesGone(uid); e != nil {
		return e
	}
	return workerProcessesGone(r)
}

// FenceDaemonWorkers preserves the original units and observes every matching
// process before stopping. Shared transition revocation precedes this host action.
// Native is quiesced under the existing peer gate before its policy listener stops.
func FenceDaemonWorkers(ctx context.Context, id, node, hash string, b *RadiusBackend, attempt int64, resume bool) (string, error) {
	if os.Geteuid() != 0 || b == nil || len(hash) != 64 || strings.Trim(hash, "0123456789abcdef") != "" || (node != "radius-primary" && node != "radius-secondary") {
		return "", errors.New("root exact worker fence required")
	}
	dir, e := writerReceiptDirectory(id)
	if e != nil {
		return "", e
	}
	r, raw, e := loadWorkerFence(id, node, hash, attempt)
	if e == nil {
		complete, ce := readPrivateCache(filepath.Join(dir, "worker-complete"), 128)
		if ce == nil {
			if string(complete) != digestBytes(raw) {
				return "", errors.New("worker completion differs")
			}
			if e = verifyWorkerFence(ctx, r, b); e != nil {
				return "", e
			}
			return digestBytes(raw), nil
		}
		if !errors.Is(ce, os.ErrNotExist) {
			return "", ce
		}
		if !resume {
			return "", errors.New("incomplete worker fence requires exact explicit resume")
		}
		processes, e := scanWriterProcesses()
		if e != nil {
			return "", e
		}
		for _, p := range processes {
			if p.PID == r.Helper.PID && p.Start == r.Helper.Start {
				return "", errors.New("original worker fence helper remains active")
			}
		}
		if e = validateWorkerResume(ctx, r, b, processes); e != nil {
			return "", e
		}
		if e = validateWorkerUnits(r, false); e != nil {
			return "", e
		}
	} else if errors.Is(e, os.ErrNotExist) && !resume {
		r = workerFence{Version: 1, Attempt: attempt, Transition: id, Node: node, ConfigSHA256: hash}
		processes, e := scanWriterProcesses()
		if e != nil {
			return "", e
		}
		r.Processes = daemonProcessEvidence(processes, os.Getpid())
		r.NativeGeneration, r.NativeModuleSHA256, e = nativeAuthGeneration()
		if e != nil {
			return "", e
		}
		active, e := b.Running(ctx)
		if e != nil {
			return "", e
		}
		if active {
			r.Native, e = b.nativeProducer(ctx)
			if e != nil {
				return "", e
			}
		}
		for _, p := range processes {
			if p.PID == os.Getpid() {
				r.Helper = writerPID{p.PID, p.Start}
			}
		}
		if r.Helper.Start == 0 {
			return "", errors.New("worker helper identity unavailable")
		}
		expected, e := systemd.Render()
		if e != nil {
			return "", e
		}
		for _, unit := range daemonWorkerUnits {
			path := "/etc/systemd/system/" + unit
			saved, e := Snapshot(File{Path: path})
			if e != nil || !saved.Exists || saved.UID != 0 || saved.GID != 0 || saved.Mode != 0644 || !bytes.Equal(saved.Data, expected[path]) {
				return "", errors.New("worker unit differs from protected current release")
			}
			r.Units = append(r.Units, saved)
		}
		raw, e = json.Marshal(r)
		if e != nil {
			return "", e
		}
		if e = privateWrite(filepath.Join(dir, "worker-original.json"), raw, 0600); e != nil {
			return "", e
		}
		if e = syncWriterDirectory(dir); e != nil {
			return "", e
		}
	} else {
		return "", e
	}
	if e = validateMaskTemporaries(writerUnitPaths(daemonWorkerUnits)); e != nil {
		return "", e
	}
	if e = b.Quiesce(ctx); e != nil {
		return "", e
	}
	for _, saved := range r.Units {
		if e = maskWriterUnit(saved.Path); e != nil {
			return "", e
		}
	}
	if _, e = b.command(ctx, "/usr/bin/systemctl", "daemon-reload"); e != nil {
		return "", e
	}
	for _, unit := range daemonWorkerUnits {
		if _, e = b.command(ctx, "/usr/bin/systemctl", "stop", unit); e != nil {
			return "", e
		}
	}
	if e = verifyWorkerFence(ctx, r, b); e != nil {
		return "", e
	}
	digest := digestBytes(raw)
	if e = privateWrite(filepath.Join(dir, "worker-complete"), []byte(digest), 0600); e != nil {
		return "", e
	}
	return digest, syncWriterDirectory(dir)
}
func VerifyDaemonWorkerFence(ctx context.Context, id, node, hash string, b *RadiusBackend) (string, error) {
	r, raw, e := loadWorkerFence(id, node, hash, 0)
	if e != nil {
		return "", e
	}
	dir, e := writerReceiptDirectory(id)
	if e != nil {
		return "", e
	}
	complete, e := readPrivateCache(filepath.Join(dir, "worker-complete"), 128)
	if e != nil || string(complete) != digestBytes(raw) {
		return "", errors.New("completed worker fence unavailable")
	}
	if e = verifyWorkerFence(ctx, r, b); e != nil {
		return "", e
	}
	return digestBytes(raw), nil
}

func validateWorkerResume(ctx context.Context, r workerFence, b *RadiusBackend, processes []writerProcess) error {
	generation, module, e := nativeAuthGeneration()
	if e != nil || generation != r.NativeGeneration || module != r.NativeModuleSHA256 {
		return errors.New("original native generation changed during worker fencing")
	}
	for _, p := range daemonProcessEvidence(processes, os.Getpid()) {
		if !slices.Contains(r.Processes, p) {
			return errors.New("new daemon/helper generation blocks worker fence recovery")
		}
	}
	active, e := b.Running(ctx)
	if e != nil {
		return e
	}
	if active {
		producer, e := b.nativeProducer(ctx)
		if e != nil || producer != r.Native {
			return errors.New("native producer generation changed during worker fencing")
		}
	}
	return nil
}
