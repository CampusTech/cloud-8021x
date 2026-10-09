package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"net"
	"slices"
	"strconv"
	"strings"

	"github.com/CampusTech/cloud-8021x/tests/runtime/task11-passive-audit/contract"
)

func parseStat(raw []byte) (uint64, int, error) {
	// comm may contain spaces and parentheses. Field 22 is starttime.
	at := bytes.LastIndexByte(raw, ')')
	if at < 0 {
		return 0, 0, errors.New("process stat malformed")
	}
	fields := strings.Fields(string(raw[at+1:]))
	if len(fields) < 20 {
		return 0, 0, errors.New("process stat truncated")
	}
	parent, e := strconv.Atoi(fields[1])
	if e != nil || parent < 0 {
		return 0, 0, errors.New("process parent malformed")
	}
	start, e := strconv.ParseUint(fields[19], 10, 64)
	if e != nil || start == 0 {
		return 0, 0, errors.New("process start malformed")
	}
	return start, parent, nil
}
func socketAddress(raw string) (string, error) {
	h, p, ok := strings.Cut(raw, ":")
	if !ok {
		return "", errors.New("socket address malformed")
	}
	v, e := hex.DecodeString(h)
	if e != nil || (len(v) != 4 && len(v) != 16) {
		return "", errors.New("socket IP malformed")
	}
	// Linux exposes each native 32-bit word in host byte order on the pinned
	// little-endian AMD64/ARM64 targets, including the four IPv6 words.
	for i := 0; i < len(v); i += 4 {
		word := binary.LittleEndian.Uint32(v[i : i+4])
		binary.BigEndian.PutUint32(v[i:i+4], word)
	}
	port, e := strconv.ParseUint(p, 16, 16)
	if e != nil {
		return "", errors.New("socket port malformed")
	}
	return net.JoinHostPort(net.IP(v).String(), strconv.FormatUint(port, 10)), nil
}
func parseSockets(raw []byte, protocol string) ([]contract.Socket, error) {
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	scanner.Buffer(make([]byte, 4096), 65536)
	if !scanner.Scan() || !strings.Contains(scanner.Text(), "local_address") || !strings.Contains(scanner.Text(), "inode") {
		return nil, errors.New("socket table header unknown")
	}
	out := []contract.Socket{}
	for scanner.Scan() {
		f := strings.Fields(scanner.Text())
		if len(f) < 10 || len(out) >= 4096 {
			return nil, errors.New("socket table malformed or unbounded")
		}
		local, e := socketAddress(f[1])
		if e != nil {
			return nil, e
		}
		remote, e := socketAddress(f[2])
		if e != nil {
			return nil, e
		}
		state, e := strconv.ParseUint(f[3], 16, 8)
		if e != nil || state == 0 || state > 12 {
			return nil, errors.New("socket state unknown")
		}
		inode, e := strconv.ParseUint(f[9], 10, 64)
		if e != nil {
			return nil, errors.New("socket inode malformed")
		}
		out = append(out, contract.Socket{Protocol: protocol, Local: local, Remote: remote, State: strings.ToUpper(f[3]), Inode: inode})
	}
	return out, scanner.Err()
}

func unitProperties(name string) []string {
	keys := []string{"Id", "LoadState", "ActiveState", "SubState", "UnitFileState", "ConditionResult", "FragmentPath", "DropInPaths", "Triggers"}
	if slices.Contains(contract.Services, name) {
		keys = append(keys, "ControlGroup", "MainPID", "ControlPID")
	}
	return keys
}
func parseUnit(raw, name string) (contract.Unit, error) {
	var out contract.Unit
	keys := unitProperties(name)
	fields := map[string]string{}
	for _, line := range strings.Split(raw, "\n") {
		if line == "" {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok || !slices.Contains(keys, k) {
			return out, errors.New("unknown systemd property")
		}
		if _, seen := fields[k]; seen {
			return out, errors.New("duplicate systemd property")
		}
		fields[k] = v
	}
	if len(fields) != len(keys) || fields["Id"] != name {
		return out, errors.New("systemd unit identity incomplete")
	}
	main, control := 0, 0
	var e error
	if slices.Contains(contract.Services, name) {
		main, e = strconv.Atoi(fields["MainPID"])
		if e != nil || main < 0 {
			return out, errors.New("service MainPID invalid")
		}
		control, e = strconv.Atoi(fields["ControlPID"])
		if e != nil || control < 0 {
			return out, errors.New("service ControlPID invalid")
		}
	}
	out = contract.Unit{Name: name, LoadState: fields["LoadState"], ActiveState: fields["ActiveState"], SubState: fields["SubState"], UnitFileState: fields["UnitFileState"], ConditionResult: fields["ConditionResult"], FragmentPath: fields["FragmentPath"], DropInPaths: fields["DropInPaths"], Triggers: fields["Triggers"], ControlGroup: fields["ControlGroup"], MainPID: main, ControlPID: control}
	return out, nil
}
