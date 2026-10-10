package main

import "testing"

// The installed Debian 13 fixture reports /usr/sbin/ip -> ../bin/ip.
// Its authenticated regular executable must be pinned through /usr/bin/ip.
func TestMeasuredDebianIPExecutablePlan(t *testing.T) {
	for _, tc := range []struct {
		name     string
		path     string
		accepted bool
	}{
		{"canonical-executable", "/usr/bin/ip", true},
		{"symlink-alias", "/usr/sbin/ip", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := validPlan()
			v := p.Tools["ip"]
			v.Path = tc.path
			p.Tools["ip"] = v
			err := p.validate()
			if (err == nil) != tc.accepted {
				t.Fatalf("measured Debian executable %s: accepted=%t, want %t; error=%v", tc.path, err == nil, tc.accepted, err)
			}
		})
	}
}
