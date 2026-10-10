package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"os"
	"runtime"
	"time"

	sc "github.com/CampusTech/cloud-8021x/tests/runtime/task11-acceptance/scenariocontract"
	"golang.org/x/sys/unix"
)

func decodeNASAction(action string, raw []byte) (decodedNASInput, error) {
	input, e := decodeNASInput(raw)
	if e != nil {
		return input, e
	}
	if input.Request.Action != action {
		return decodedNASInput{}, errors.New("argv differs from sole pinned native Request")
	}
	return input, nil
}
func syntheticNASMarker() error {
	if runtime.GOOS != "linux" || runtime.GOARCH != "arm64" || os.Geteuid() != 0 {
		return errors.New("enrolled synthetic Linux ARM root required")
	}
	fd, e := unix.Open("/etc/cloud8021x-task11-fixture", unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if e != nil {
		return errors.New("protected synthetic marker unavailable")
	}
	file := os.NewFile(uintptr(fd), "fixed-fixture-marker")
	defer func() { _ = file.Close() }()
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Uid != 0 || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Mode&07777 != 0644 || st.Nlink != 1 || st.Size != 18 {
		return errors.New("protected synthetic marker differs")
	}
	marker, e := io.ReadAll(io.LimitReader(file, 19))
	if e != nil || !bytes.Equal(marker, []byte("synthetic-only-v1\n")) {
		return errors.New("synthetic marker differs")
	}
	return nil
}
func runNAS(ctx context.Context, action string, raw []byte) ([]byte, error) {
	input, e := decodeNASAction(action, raw)
	if e != nil {
		return nil, e
	}
	if ctx == nil || ctx.Err() != nil {
		return nil, errors.New("bounded live NAS context required")
	}
	if e = syntheticNASMarker(); e != nil {
		return nil, e
	}
	material := map[string][]byte{}
	defer func() {
		for _, v := range material {
			clear(v)
		}
	}()
	for _, name := range nasMaterialNames {
		v, e := readProtectedNASMaterial(nasMaterialRoot, name, input.Plan.Materials[name], 0)
		if e != nil {
			return nil, e
		}
		material[name] = v
	}
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	var body any
	if input.Request.Authority != "" {
		execution, e := prepareCAExecution(input, material, time.Now().UTC())
		if e != nil {
			return nil, e
		}
		result, e := executeCA(ctx, execution)
		if e != nil {
			return nil, e
		}
		body = result
	} else {
		if e = validateNativeMaterials(input.Plan, material); e != nil {
			return nil, e
		}
		executable, e := openNativeELFAt("/usr/bin/eapol_test", nativeELFSHA256, 0)
		if e != nil {
			return nil, e
		}
		defer func() { _ = executable.Close() }()
		chosen := time.Now().UTC()
		actual, class, e := runNativeEAP(ctx, input.Plan, material["radius-secret"], executable)
		if e != nil {
			return nil, e
		}
		if !actual.Accepted {
			body = nativeRejectedBody(input.Plan, actual, chosen)
		} else {
			prepared, e := prepareNativeAccounting(input.Plan, actual, class, material["class-key"], material["radius-secret"], time.Now().UTC(), rand.Reader)
			if e != nil {
				return nil, e
			}
			prepared.result.ChosenAt = chosen
			defer func() {
				for _, v := range prepared.transmissions {
					clear(v.packet)
				}
			}()
			for _, v := range prepared.transmissions {
				result, e := sendNativeAccounting(ctx, v, material["radius-secret"])
				if e != nil {
					return nil, e
				}
				prepared.result.Packets = append(prepared.result.Packets, result)
			}
			body = prepared.result
		}
	}
	public, e := json.Marshal(body)
	if e != nil || len(public) > 64<<10 {
		return nil, errors.New("bounded public native body unavailable")
	}
	return public, nil
}

func nativeRejectedBody(p nasPrivatePlan, actual sc.EAPResult, chosen time.Time) sc.NASResult {
	return sc.NASResult{Peer: p.Scenario.Target, Session: p.Scenario.Session, Station: p.Station, ChosenAt: chosen, EAP: actual}
}
