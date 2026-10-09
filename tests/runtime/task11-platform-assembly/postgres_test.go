package main

import (
	"strings"
	"testing"
)

func TestPGInitializerStaysInExactRootNamespaceAndBoundedPrivateDevices(t *testing.T) {
	for _, program := range []string{"initdb", "pg_isready", "psql"} {
		args, e := pgTransient(program)
		if e != nil {
			t.Fatal(e)
		}
		joined := strings.Join(args, "\n")
		for _, required := range []string{"--property=RootDirectory=" + platformRoot + "/aux/pg", "--property=NetworkNamespacePath=/run/netns/c11-pg", "--property=User=postgres", "--property=Group=postgres", "--property=PrivateDevices=yes", "--property=MountAPIVFS=yes", "--property=RuntimeMaxSec=60", "--property=KillMode=control-group"} {
			if !strings.Contains(joined, required) {
				t.Fatalf("PG escape/missing bound %s", required)
			}
		}
	}
	if _, e := pgTransient("sh", "-c", "anything"); e == nil {
		t.Fatal("injected executor admitted")
	}
	if !strings.Contains(pgUnit(), "NetworkNamespacePath=/run/netns/c11-pg") {
		t.Fatal("outage target unit lost PG isolation")
	}
}
