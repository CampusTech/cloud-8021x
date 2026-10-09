package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestCLIRefusesArbitraryArgumentsAndUnknownRequestWithoutResult(t *testing.T) {
	for _, tc := range []struct {
		args  []string
		input string
	}{{[]string{"observe", "/etc/shadow"}, "{}"}, {[]string{"observe", "--config", "/tmp/x"}, "{}"}, {[]string{"observe"}, `{"Schema":1,"Unknown":"value"}`}, {[]string{"observe"}, strings.Repeat("x", (16<<10)+1)}} {
		cmd := command()
		var out bytes.Buffer
		cmd.SetArgs(tc.args)
		cmd.SetIn(strings.NewReader(tc.input))
		cmd.SetOut(&out)
		cmd.SetErr(&out)
		if cmd.Execute() == nil || out.Len() != 0 {
			t.Fatal("unsafe CLI produced success/result", out.String())
		}
	}
}
