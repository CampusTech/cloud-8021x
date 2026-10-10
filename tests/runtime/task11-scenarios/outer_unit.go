package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

type controllerUnitState struct {
	active, sub, result string
	pid, status         int
}

func parseControllerUnit(raw []byte) (controllerUnitState, error) {
	var s controllerUnitState
	if len(raw) == 0 || len(raw) > 4096 {
		return s, errors.New("bounded unit observation required")
	}
	values := map[string]string{}
	for _, line := range strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return s, errors.New("unit observation malformed")
		}
		if _, duplicate := values[key]; duplicate {
			return s, errors.New("duplicate unit field")
		}
		values[key] = value
	}
	if len(values) != 7 || values["FragmentPath"] != "/etc/systemd/system/task11-acceptance.service" || values["DropInPaths"] != "" {
		return s, errors.New("fixed shipping fixture unit and no dropins required")
	}
	for key := range values {
		switch key {
		case "ActiveState", "SubState", "MainPID", "Result", "ExecMainStatus", "FragmentPath", "DropInPaths":
		default:
			return s, errors.New("unknown unit field")
		}
	}
	pid, e := strconv.Atoi(values["MainPID"])
	status, other := strconv.Atoi(values["ExecMainStatus"])
	if e != nil || other != nil || pid < 0 || status < 0 || status > 255 {
		return s, errors.New("invalid unit process observation")
	}
	s = controllerUnitState{active: values["ActiveState"], sub: values["SubState"], result: values["Result"], pid: pid, status: status}
	switch s.active {
	case "inactive", "active", "activating", "deactivating", "failed":
	default:
		return s, errors.New("unknown controller active state")
	}
	return s, nil
}

// A named private buffer prevents promoted ReadFrom from bypassing this cap.
type controllerOutput struct {
	data  bytes.Buffer
	limit int
}

func (b *controllerOutput) Write(p []byte) (int, error) {
	if len(p) > b.limit-b.data.Len() {
		return 0, errors.New("bounded controller output exceeded")
	}
	return b.data.Write(p)
}
func systemctlFixed(ctx context.Context, args ...string) ([]byte, error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, errors.New("live bounded controller context required")
	}
	child, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(child, "/usr/bin/systemctl", args...)
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LANG=C", "SYSTEMD_COLORS=0"}
	cmd.Stderr = io.Discard
	out := controllerOutput{limit: 4096}
	cmd.Stdout = &out
	cmd.WaitDelay = time.Second
	if e := cmd.Run(); e != nil {
		return nil, errors.New("fixed controller service operation failed")
	}
	return append([]byte(nil), out.data.Bytes()...), nil
}
func queryControllerUnit(ctx context.Context) (controllerUnitState, error) {
	raw, e := systemctlFixed(ctx, "show", "task11-acceptance.service", "--property=ActiveState,SubState,MainPID,Result,ExecMainStatus,FragmentPath,DropInPaths", "--no-pager")
	if e != nil {
		return controllerUnitState{}, e
	}
	return parseControllerUnit(raw)
}
func controllerFinished(s controllerUnitState) bool {
	return s.active == "inactive" && s.sub == "dead" && s.pid == 0 && s.status == 0 && s.result == "success"
}
