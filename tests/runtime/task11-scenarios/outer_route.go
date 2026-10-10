package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"time"

	sc "github.com/CampusTech/cloud-8021x/tests/runtime/task11-acceptance/scenariocontract"
	"golang.org/x/sys/unix"
)

const outerControl = "/var/lib/cloud8021x-task11/control"

type liveControllerRoute struct {
	store     *outerStore
	controlFD int
}

func (r *liveControllerRoute) publishRequest(request sc.Request, raw []byte) error {
	if decoded, e := sc.DecodeRequest(raw); e != nil || decoded.AttemptID != request.AttemptID || decoded.Sequence != request.Sequence {
		return errors.New("strict raw controller request differs")
	}
	name, e := request.RecordName()
	if e != nil {
		return e
	}
	return r.store.create("requests", name, raw)
}
func (r *liveControllerRoute) checkControl() error {
	current, e := protectedDirectoryAt(outerControl, 0)
	if e != nil {
		return e
	}
	defer func() { _ = unix.Close(current) }()
	var expected, actual unix.Stat_t
	if unix.Fstat(r.controlFD, &expected) != nil || unix.Fstat(current, &actual) != nil || outerIdentity(expected) != outerIdentity(actual) {
		return errors.New("protected control descriptor replaced")
	}
	return r.store.check()
}
func (r *liveControllerRoute) writeStage(stage sc.Stage) error {
	raw, e := json.Marshal(stage)
	if e != nil {
		return e
	}
	if _, e = sc.DecodeStage(raw); e != nil {
		return e
	}
	if r.checkControl() != nil {
		return errors.New("controller store identity changed")
	}
	existing, e := unix.Openat(r.controlFD, "stage.json", unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if e == nil {
		var st unix.Stat_t
		valid := unix.Fstat(existing, &st) == nil && privateRecordStat(st, 0, 4096)
		_ = unix.Close(existing)
		if !valid {
			return errors.New("prior protected stage differs")
		}
	} else if e != unix.ENOENT {
		return errors.New("prior protected stage unavailable")
	}
	fd, e := unix.Openat(r.controlFD, "stage.scenario-next", unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if e != nil {
		return errors.New("retained stage publication refuses retry")
	}
	file := os.NewFile(uintptr(fd), "scenario-stage")
	defer func() { _ = file.Close() }()
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || !privateRecordStat(st, 0, 4096) {
		return errors.New("new protected stage differs")
	}
	n, e := file.Write(raw)
	if e != nil || n != len(raw) || file.Sync() != nil || unix.Renameat(r.controlFD, "stage.scenario-next", r.controlFD, "stage.json") != nil || unix.Fsync(r.controlFD) != nil {
		return errors.New("protected stage publication incomplete")
	}
	return nil
}
func (r *liveControllerRoute) dispatch(ctx context.Context, stage sc.Stage) error {
	before, e := queryControllerUnit(ctx)
	if e != nil || !controllerFinished(before) {
		return errors.New("fixed prior controller must be retired successfully")
	}
	if e = r.writeStage(stage); e != nil {
		return e
	}
	if e = r.checkControl(); e != nil {
		return e
	}
	if _, e = systemctlFixed(ctx, "start", "task11-acceptance.service"); e != nil {
		return e
	}
	deadline := time.NewTimer(10 * time.Minute)
	defer deadline.Stop()
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	for {
		state, e := queryControllerUnit(ctx)
		if e != nil {
			return e
		}
		if controllerFinished(state) {
			return nil
		}
		if state.active == "failed" || state.active == "inactive" {
			return errors.New("controller failed before actual retirement result")
		}
		select {
		case <-ctx.Done():
			return errors.New("controller completion uncertain; reconcile retained claim")
		case <-deadline.C:
			return errors.New("controller retirement timeout; reconcile retained claim")
		case <-tick.C:
		}
	}
}
func (r *liveControllerRoute) readResult(ctx context.Context, request sc.Request) ([]byte, error) {
	if ctx.Err() != nil {
		return nil, errors.New("cancelled result read")
	}
	name, e := request.RecordName()
	if e != nil {
		return nil, e
	}
	failure, e := r.store.read("failures", name, 4096)
	clear(failure)
	if e == nil {
		return nil, errors.New("actual controller published a failure")
	}
	if !errors.Is(e, unix.ENOENT) {
		return nil, e
	}
	return r.store.read("results", name, sc.MaxResultBytes)
}
func lockOuterControl() (int, *os.File, error) {
	fd, e := protectedDirectoryAt(outerControl, 0)
	if e != nil {
		return -1, nil, e
	}
	child, e := unix.Openat(fd, "scenario-driver.lock", unix.O_RDWR|unix.O_CREAT|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if e != nil {
		_ = unix.Close(fd)
		return -1, nil, e
	}
	file := os.NewFile(uintptr(child), "scenario-driver-lock")
	var st unix.Stat_t
	if unix.Fstat(child, &st) != nil || !privateRecordStat(st, 0, 0) || unix.Flock(child, unix.LOCK_EX|unix.LOCK_NB) != nil {
		_ = file.Close()
		_ = unix.Close(fd)
		return -1, nil, errors.New("another driver or unsafe lock blocks execution")
	}
	return fd, file, nil
}

func (r *liveControllerRoute) invoke(ctx context.Context, request sc.Request) (retiredOperation, error) {
	result, raw, e := submitOperation(ctx, r, request)
	return retiredOperation{request: request, result: result, raw: raw}, e
}
