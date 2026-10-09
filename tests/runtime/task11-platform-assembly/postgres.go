package main

import "errors"

func pgTransient(program string, args ...string) ([]string, error) {
	names := map[string]string{"initdb": "init", "pg_isready": "ready", "psql": "roles"}
	name, ok := names[program]
	if !ok {
		return nil, errors.New("unapproved PostgreSQL initializer executable")
	}
	out := []string{"--unit=task11-pg-" + name, "--collect", "--quiet", "--wait", "--pipe", "--service-type=exec", "--property=RootDirectory=" + platformRoot + "/aux/pg", "--property=NetworkNamespacePath=/run/netns/c11-pg", "--property=User=postgres", "--property=Group=postgres", "--property=PrivateDevices=yes", "--property=MountAPIVFS=yes", "--property=RuntimeMaxSec=60", "--property=KillMode=control-group", "--property=TimeoutStopSec=5", "/usr/lib/postgresql/17/bin/" + program}
	return append(out, args...), nil
}
func (o operation) pg(program string, args ...string) error {
	argv, e := pgTransient(program, args...)
	if e != nil {
		return e
	}
	return o.call("systemd-run", argv...)
}
