package main

import (
	"strconv"
	"strings"
)

func controlCleanupRole(s string) bool { return s == "worker" || s == "leaf" || s == "sentinel" }
func parseControlPIDLine(raw []byte) (int, error) {
	if len(raw) < 2 || len(raw) > 32 || raw[len(raw)-1] != '\n' {
		return 0, errScenarioControl
	}
	s := strings.TrimSuffix(string(raw), "\n")
	n, err := strconv.Atoi(s)
	if err != nil || n < 2 || strconv.Itoa(n) != s {
		return 0, errScenarioControl
	}
	return n, nil
}

type controlProbeFrame struct{ helper, leaf int }

func parseControlProbeLine(raw []byte) (controlProbeFrame, error) {
	var frame controlProbeFrame
	if len(raw) < 4 || len(raw) > 64 || raw[len(raw)-1] != '\n' {
		return frame, errScenarioControl
	}
	parts := strings.Split(strings.TrimSuffix(string(raw), "\n"), " ")
	if len(parts) != 2 {
		return frame, errScenarioControl
	}
	var err error
	frame.helper, err = parseControlPIDLine([]byte(parts[0] + "\n"))
	if err != nil {
		return frame, err
	}
	frame.leaf, err = parseControlPIDLine([]byte(parts[1] + "\n"))
	return frame, err
}

// Status comes from the retained outer procfs mount. Both levels must be
// measured: a local PID or a namespace inode alone cannot prove guest entry.
func controlPIDMapping(status []byte) (int, int, error) {
	if len(status) == 0 || len(status) > 64<<10 {
		return 0, 0, errScenarioControl
	}
	var pid, host, local int
	seenPID, seenNS := false, false
	for _, line := range strings.Split(string(status), "\n") {
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		switch key {
		case "Pid":
			if seenPID {
				return 0, 0, errScenarioControl
			}
			seenPID = true
			var err error
			pid, err = parseControlPIDLine([]byte(strings.TrimSpace(value) + "\n"))
			if err != nil {
				return 0, 0, errScenarioControl
			}
		case "NSpid":
			if seenNS {
				return 0, 0, errScenarioControl
			}
			seenNS = true
			fields := strings.Fields(value)
			if len(fields) != 2 {
				return 0, 0, errScenarioControl
			}
			var err error
			host, err = parseControlPIDLine([]byte(fields[0] + "\n"))
			if err != nil {
				return 0, 0, errScenarioControl
			}
			local, err = parseControlPIDLine([]byte(fields[1] + "\n"))
			if err != nil {
				return 0, 0, errScenarioControl
			}
		}
	}
	if !seenPID || !seenNS || pid != host {
		return 0, 0, errScenarioControl
	}
	return host, local, nil
}
func validateControlNamespace(status []byte, hostPID, localPID int, expected, actual, outer uint64) error {
	if hostPID < 2 || localPID < 2 || expected == 0 || actual != expected || outer == 0 || expected == outer {
		return errScenarioControl
	}
	host, local, err := controlPIDMapping(status)
	if err != nil || host != hostPID || local != localPID {
		return errScenarioControl
	}
	return nil
}
