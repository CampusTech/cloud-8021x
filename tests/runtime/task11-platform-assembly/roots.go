package main

import (
	"errors"
	"os"
	"path"
	"sort"
	"strings"
)

func (o operation) privateRoots() error {
	for _, n := range o.in.Plan.Nodes {
		size := int64(256) * MiB
		if strings.HasPrefix(n.Name, "green-") {
			size = 768 * MiB
		}
		root := rootFor(n.Name)
		if e := o.overlay(n.Name, root, size); e != nil {
			return e
		}
		if e := o.populateNode(n); e != nil {
			return e
		}
	}
	for _, a := range []struct {
		name string
		size int64
	}{{"api", 128 * MiB}, {"pg", 256 * MiB}, {"nas", 64 * MiB}} {
		root := platformRoot + "/aux/" + a.name
		if e := o.overlay(a.name, root, a.size); e != nil {
			return e
		}
		if e := replaceFile(root+"/etc/cloud8021x-task11-fixture", []byte("synthetic-only-v1\n"), 0644, 0, 0); e != nil {
			return e
		}
		if e := replaceFile(root+"/etc/hosts", localHosts(o.in), 0644, 0, 0); e != nil {
			return e
		}
	}
	// Each API gate has distinct private state. Bind the same actual backing into
	// the outer verifier and the API root; never reconstruct a journal or receipt.
	apiVolume := platformRoot + "/volumes/api"
	for _, gate := range []string{"installed", "primitive"} {
		dst := apiVolume + "/" + gate
		src := originalRoot + "/api"
		if gate == "primitive" {
			src = controlRoot + "/primitive-api"
		}
		if e := directory(dst, 0700); e != nil {
			return e
		}
		if gate == "installed" {
			for f, b := range o.in.Original {
				if strings.HasPrefix(f, "api/") {
					if e := publish(dst+"/"+strings.TrimPrefix(f, "api/"), b, 0600); e != nil {
						return e
					}
				}
			}
		} else {
			for f, b := range o.in.Primitive {
				if e := publish(dst+"/"+f, b, 0600); e != nil {
					return e
				}
			}

		}
		if e := o.call("mount", "--bind", dst, src); e != nil {
			return e
		}
	}
	pg := platformRoot + "/aux/pg"
	uids, gids, e := accountIDs(pg)
	if e != nil {
		return e
	}
	uid, ok := uids["postgres"]
	if !ok {
		return errors.New("real PostgreSQL package user absent")
	}
	gid, ok := gids["postgres"]
	if !ok {
		return errors.New("real PostgreSQL package group absent")
	}
	for f, b := range o.in.Original {
		if strings.HasPrefix(f, "postgres/") {
			if e = replaceFile(pg+"/etc/task11-postgres/"+path.Base(f), b, 0600, uid, gid); e != nil {
				return e
			}
		}
	}
	if e = directory(pg+"/etc/task11-postgres", 0755); e != nil {
		return e
	}
	if e = directory(pg+"/var/lib/postgresql", 0755); e != nil {
		return e
	}
	if e = directory(pg+"/var/lib/postgresql/17", 0755); e != nil {
		return e
	}
	if e = os.Chown(pg+"/var/lib/postgresql/17", uid, gid); e != nil {
		return e
	}
	if e = directory(pg+"/var/lib/postgresql/run", 0755); e != nil {
		return e
	}
	if e = os.Chown(pg+"/var/lib/postgresql/run", uid, gid); e != nil {
		return e
	}
	// NAS owns only public helper/executables; its future private packet inputs
	// come from the separate independently reviewed scenario driver.
	return o.bindPublic(o.in.Plan.Helpers["task11-systemd-fixture"], platformRoot+"/aux/nas/usr/local/libexec/task11-systemd-fixture")
}
func (o operation) populateNode(n node) error {
	root := rootFor(n.Name)
	for _, d := range []string{"/usr/local/bin", "/usr/local/libexec", "/etc/cloud-8021x", "/etc/acme-authz-webhook", "/etc/freeradius", "/etc/freeradius/3.0", "/etc/freeradius/3.0/certs", "/etc/systemd/system", "/var/cache/cloud-8021x/artifacts"} {
		if e := directory(root+d, 0755); e != nil {
			return e
		}
	}
	fixed := map[string][]byte{"/etc/machine-id": []byte(n.MachineID + "\n"), "/etc/hostname": []byte("task11-" + n.Name + "\n"), "/etc/hosts": localHosts(o.in), "/etc/resolv.conf": []byte("# isolated fixture: hosts-only\n"), "/etc/nsswitch.conf": []byte("passwd: files\ngroup: files\nshadow: files\nhosts: files\n"), "/etc/cloud8021x-task11-fixture": []byte("synthetic-only-v1\n"), "/etc/systemd/system/task11-metadata.service": []byte(metadataUnit(n))}
	for p, b := range fixed {
		if e := replaceFile(root+p, b, 0644, 0, 0); e != nil {
			return e
		}
	}
	if e := linkFile(root+"/etc/systemd/system/multi-user.target.wants/task11-metadata.service", "../task11-metadata.service"); e != nil {
		return e
	}
	if e := directory(root+"/var/lib/cloud8021x-task11-metadata", 0700); e != nil {
		return e
	}
	seed := o.in.Original["metadata/task11-"+n.Name+"/seed.json"]
	if len(seed) == 0 {
		return errors.New("distinct metadata seed missing")
	}
	if e := publish(root+"/var/lib/cloud8021x-task11-metadata/seed.json", seed, 0600); e != nil {
		return e
	}
	ca, e := readProtected(root+"/etc/ssl/certs/ca-certificates.crt", 4<<20)
	if e != nil || len(ca) > 4<<20 {
		return errors.New("package trust store unavailable")
	}
	ca = append(append(ca, '\n'), o.in.Original[o.in.Seed.APICA.Path]...)
	if e = replaceFile(root+"/usr/local/share/ca-certificates/task11-api.crt", o.in.Original[o.in.Seed.APICA.Path], 0644, 0, 0); e != nil {
		return e
	}
	if strings.HasPrefix(n.Name, "blue-") {
		originalWebhook := o.in.Original["source/etc/acme-authz-webhook/server.crt"]
		if len(originalWebhook) == 0 {
			return errors.New("original loopback trust absent")
		}
		ca = append(append(ca, '\n'), originalWebhook...)
		if e = replaceFile(root+"/usr/local/share/ca-certificates/acme-webhook.crt", originalWebhook, 0644, 0, 0); e != nil {
			return e
		}
	}

	if e = replaceFile(root+"/etc/ssl/certs/ca-certificates.crt", ca, 0644, 0, 0); e != nil {
		return e
	}
	if strings.HasPrefix(n.Name, "blue-") {
		if e = o.blueAccounts(root); e != nil {
			return e
		}
	}
	uids, gids, e := accountIDs(root)
	if e != nil {
		return e
	}
	names := []string{}
	for name := range o.in.Index.Files {
		if strings.HasPrefix(name, n.Name+"/") {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	for _, name := range names {
		c := o.in.Index.Files[name]
		uid, ok := uids[c.Owner]
		if !ok {
			return errors.New("candidate account absent")
		}
		gid, ok := gids[c.Group]
		if !ok {
			return errors.New("candidate group absent")
		}
		if e = replaceFile(root+strings.TrimPrefix(name, n.Name), o.in.Files[name], c.Mode, uid, gid); e != nil {
			return e
		}
	}
	for _, r := range o.in.Index.References[n.Name] {
		if e = replaceFile(root+r.Destination, nil, 0600, 0, 0); e != nil {
			return e
		}
	}
	if e = replaceFile(root+"/usr/local/libexec/task11-cloud-contract", nil, 0600, 0, 0); e != nil {
		return e
	}
	if n.Name == "blue-primary" {
		if e = replaceFile(root+"/usr/local/libexec/task11-blue-migration", nil, 0600, 0, 0); e != nil {
			return e
		}
		for _, f := range []string{"assembly-input.json", "api/seed.json"} {
			var b []byte
			if f == "assembly-input.json" {
				b, e = readPinned(originalRoot+"/"+f, o.in.Plan.InputSHA256, 1<<20, true)
			} else {
				b = o.in.Original[f]
			}
			if e != nil {
				return e
			}
			if e = publish(root+originalRoot+"/"+f, b, 0600); e != nil {
				return e
			}
		}
		b, e := readPinned(controlRoot+"/blue-migration.json", o.in.Plan.BluePlanSHA256, 16<<10, true)
		if e != nil {
			return e
		}
		if e = publish(root+controlRoot+"/blue-migration.json", b, 0600); e != nil {
			return e
		}
	}
	if strings.HasPrefix(n.Name, "blue-") {
		// Native TLS leaf custody remains freerad0700, exactly as shipping expects.
		for p, owner := range map[string]string{"/run/radius-verified-leaves": "freerad", "/run/radius-certificate-bindings": "cloud8021x", "/run/cloud-8021x/credentials": "cloud8021x", "/run/cloud-8021x-collector": "dd-agent"} {
			if e = directory(root+p, 0700); e != nil {
				return e
			}
			if e = os.Chown(root+p, uids[owner], gids[owner]); e != nil {
				return e
			}
		}
		if e = directory(root+"/run/cloud-8021x", 0755); e != nil {
			return e
		}
		if e = directory(root+"/etc/acme-authz-webhook", 0755); e != nil {
			return e
		}

	}
	return nil
}
func (o operation) units() error {
	for _, n := range o.in.Plan.Nodes {
		if e := publish("/etc/systemd/system/task11-node-"+n.Name+".service", []byte(completeNodeUnit(o.in, n)), 0644); e != nil {
			return e
		}
	}
	for name, body := range map[string]string{"task11-api-primitive.service": apiUnit("primitive"), "task11-api-installed.service": apiUnit("installed"), "task11-postgres.service": pgUnit()} {
		if e := publish("/etc/systemd/system/"+name, []byte(body), 0644); e != nil {
			return e
		}
	}
	b, e := readPinned(publicRoot+"/task11-acceptance.service", o.in.Plan.ControllerUnitSHA256, 16<<10, false)
	if e != nil {
		return e
	}
	if e = publish("/etc/systemd/system/task11-acceptance.service", b, 0644); e != nil {
		return e
	}
	for name, p := range o.in.Plan.Helpers {
		if e = o.bindPublic(p, "/usr/local/libexec/"+name); e != nil {
			return e
		}
	}
	if e = publish(controlRoot+"/enrollment.json", o.in.Files["outer"+controlRoot+"/enrollment.json"], 0600); e != nil {
		return e
	}
	return o.call("systemctl", "daemon-reload")
}

func (o operation) blueAccounts(root string) error {
	users, groups, e := accountIDs(root)
	if e != nil {
		return e
	}
	for _, name := range []string{"cloud8021x", "cloud8021x-events", "cloud8021x-spool-metadata"} {
		if _, ok := groups[name]; !ok {
			if e = o.call("chroot", root, "/usr/sbin/groupadd", "--system", name); e != nil {
				return e
			}
		}
	}
	if _, ok := users["cloud8021x"]; !ok {
		if e = o.call("chroot", root, "/usr/sbin/useradd", "--system", "--gid", "cloud8021x", "--no-create-home", "--shell", "/usr/sbin/nologin", "cloud8021x"); e != nil {
			return e
		}
	}
	if e = o.call("chroot", root, "/usr/sbin/usermod", "--groups", "cloud8021x-events,cloud8021x-spool-metadata", "--shell", "/usr/sbin/nologin", "--lock", "cloud8021x"); e != nil {
		return e
	}
	if e = o.call("chroot", root, "/usr/sbin/usermod", "--append", "--groups", "cloud8021x-events", "freerad"); e != nil {
		return e
	}
	users, groups, e = accountIDs(root)
	if e != nil {
		return e
	}
	seen := map[int]bool{}
	for _, name := range []string{"root", "cloud8021x", "freerad", "dd-agent", "postgres"} {
		id, ok := users[name]
		if !ok || seen[id] || (name != "root" && id == 0) {
			return errors.New("actual installed account separation differs")
		}
		seen[id] = true
	}
	seen = map[int]bool{}
	for _, name := range []string{"cloud8021x", "cloud8021x-events", "cloud8021x-spool-metadata"} {
		id, ok := groups[name]
		if !ok || id == 0 || seen[id] {
			return errors.New("actual installed group separation differs")
		}
		seen[id] = true
	}
	return nil
}
