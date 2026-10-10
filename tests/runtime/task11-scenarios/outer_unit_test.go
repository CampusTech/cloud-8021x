package main

import (
	"bytes"
	"io"
	"strings"
	"testing"
)

const pureUnitState = "ActiveState=inactive\nSubState=dead\nMainPID=0\nResult=success\nExecMainStatus=0\nFragmentPath=/etc/systemd/system/task11-acceptance.service\nDropInPaths=\n"

func TestOuterUnitParserRequiresExactFragmentNoDropinsAndActualRetirement(t *testing.T) {
	s, e := parseControllerUnit([]byte(pureUnitState))
	if e != nil || s.active != "inactive" || s.pid != 0 || s.status != 0 {
		t.Fatal("actual finished unit observation refused", e)
	}
	for _, raw := range []string{pureUnitState + "MainPID=7\n", strings.Replace(pureUnitState, "/etc/systemd/system/task11-acceptance.service", "/tmp/foreign.service", 1), strings.Replace(pureUnitState, "DropInPaths=", "DropInPaths=/etc/foreign.conf", 1), strings.Replace(pureUnitState, "MainPID=0", "MainPID=bogus", 1), pureUnitState + "Unknown=yes\n", strings.Repeat(" ", 4097)} {
		if _, e := parseControllerUnit([]byte(raw)); e == nil {
			t.Fatal("unknown/foreign unit accepted")
		}
	}
}

func TestControllerOutputRealIOCopyRouteEnforcesExactBoundary(t *testing.T) {
	for _, size := range []int{4096, 4097, 32769} {
		b := controllerOutput{limit: 4096}
		n, e := io.Copy(&b, bytes.NewBuffer(bytes.Repeat([]byte("x"), size)))
		if size == 4096 {
			if e != nil || n != 4096 || b.data.Len() != 4096 {
				t.Fatal("exact boundary rejected")
			}
		} else if e == nil || b.data.Len() > 4096 {
			t.Fatal("real io.Copy route bypassed output bound")
		}
	}
}
