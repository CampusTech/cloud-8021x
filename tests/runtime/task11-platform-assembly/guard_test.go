package main

import "testing"

func TestRootMarkerDoesNotAuthorizeForeignNetworkOrPartialReplay(t *testing.T) {
	good := platformFacts{Linux: true, Root: true, Systemd: true, Marker: true, Links: []string{"lo"}}
	for _, edit := range []func(*platformFacts){func(f *platformFacts) { f.Links = append(f.Links, "eth0") }, func(f *platformFacts) { f.Existing = true }, func(f *platformFacts) { f.Container = true }, func(f *platformFacts) { f.Marker = false }} {
		f := good
		edit(&f)
		if validatePlatform(f, false) == nil {
			t.Fatal("unsafe platform accepted")
		}
	}
	f := good
	f.Links = []string{"lo", "c11-foreign-h"}
	if validatePlatform(f, true) == nil {
		t.Fatal("foreign fake owned interface accepted")
	}
}
