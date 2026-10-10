package main

import (
	"context"
	"crypto/rand"
	"errors"
	"io"
	"os"
	"runtime"
	"time"

	"golang.org/x/sys/unix"
)

const scenarioExecutable = "/usr/local/libexec/task11-scenarios"

func pinOuterExecutable(pin string) error {
	if runtime.GOOS != "linux" || runtime.GOARCH != "arm64" || os.Geteuid() != 0 || !shaPattern.MatchString(pin) {
		return errors.New("enrolled root ARM helper required")
	}
	// The proc descriptor measures the currently executing helper, independently
	// of the name later rechecked by the controller's NAS transport.
	actual, e := os.Open("/proc/self/exe")
	if e != nil {
		return errors.New("actual executing helper unavailable")
	}
	defer func() { _ = actual.Close() }()
	fd, e := unix.Open(scenarioExecutable, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if e != nil {
		return errors.New("fixed installed helper unavailable")
	}
	fixed := os.NewFile(uintptr(fd), "scenario-helper")
	defer func() { _ = fixed.Close() }()
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Uid != 0 || st.Nlink != 1 || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Mode&07777 != 0755 || st.Size < 64 || st.Size > 64<<20 {
		return errors.New("fixed helper descriptor unsafe")
	}
	a, e := actual.Stat()
	b, other := fixed.Stat()
	if e != nil || other != nil || !os.SameFile(a, b) {
		return errors.New("executing helper differs from fixed installed descriptor")
	}
	raw, e := io.ReadAll(io.LimitReader(actual, (64<<20)+1))
	defer clear(raw)
	if e != nil || int64(len(raw)) != st.Size || digestBytes(raw) != pin {
		return errors.New("executing helper differs from immutable source binary pin")
	}
	return nil
}
func runOuter(ctx context.Context, caseName, pin, phase string) ([]byte, error) {
	if !outerCase(caseName) || !shaPattern.MatchString(pin) || ctx == nil || ctx.Err() != nil {
		return nil, errors.New("closed immutable scenario case and pin required")
	}
	if e := validateRunCase(caseName, phase); e != nil {
		return nil, e
	}
	if e := syntheticNASMarker(); e != nil {
		return nil, e
	}
	controlFD, lock, e := lockOuterControl()
	if e != nil {
		return nil, e
	}
	defer func() { _ = lock.Close(); _ = unix.Close(controlFD) }()
	store, e := openOuterStore(outerControl+"/scenarios", 0)
	if e != nil {
		return nil, e
	}
	defer store.close()
	raw, e := store.read("plans", caseName+".json", 64<<10)
	if e != nil {
		return nil, e
	}
	defer clear(raw)
	plan, e := decodeNASPlan(raw, pin)
	if e != nil || plan.Scenario.Case != caseName {
		return nil, errors.New("fixed protected plan case or digest differs")
	}
	if e = pinOuterExecutable(plan.Scenario.SelfSHA256); e != nil {
		return nil, e
	}
	attempt, e := bindOuterAttempt(store, plan, pin, phase, rand.Reader)
	if e != nil {
		return nil, e
	}
	history, e := retiredHistory(store, plan, attempt)
	if e != nil {
		return nil, e
	}
	route := &liveControllerRoute{store: store, controlFD: controlFD}
	child, cancel := context.WithTimeout(ctx, 20*time.Minute)
	defer cancel()
	var operations []retiredOperation
	if plan.Scenario.Scenario == "ca-continuity" {
		operations, e = executeCAActions(child, store, plan, attempt, phase, history, route.invoke)
	} else {
		if len(history) != 0 {
			return nil, errors.New("retained accounting operation refuses rerun")
		}
		operations, e = executeAccountingActions(child, plan, attempt, route.invoke)
	}
	if e != nil {
		return nil, e
	}
	return marshalPublicDriverResult(caseName, attempt, operations)
}
