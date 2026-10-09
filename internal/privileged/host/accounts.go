package host

import (
	"context"
	"errors"
	"os"
	"os/user"
	"strconv"

	"golang.org/x/sys/unix"
)

type Accounts struct{ RuntimeUID, RuntimeGID, NativeUID, NativeGID, EventsGID, SpoolGID, CollectorUID, CollectorGID int }

func identity(name string) (int, int, error) {
	u, e := user.Lookup(name)
	if e != nil {
		return 0, 0, errors.New("required installed account unavailable")
	}
	uid, e := strconv.Atoi(u.Uid)
	if e != nil || uid <= 0 {
		return 0, 0, errors.New("invalid installed UID")
	}
	gid, e := strconv.Atoi(u.Gid)
	if e != nil || gid <= 0 {
		return 0, 0, errors.New("invalid installed GID")
	}
	return uid, gid, nil
}
func ReadAccounts() (Accounts, error) {
	var a Accounts
	var e error
	a.RuntimeUID, a.RuntimeGID, e = identity("cloud8021x")
	if e != nil {
		return a, e
	}
	a.NativeUID, a.NativeGID, e = identity("freerad")
	if e != nil {
		return a, e
	}
	a.CollectorUID, a.CollectorGID, e = identity("dd-agent")
	if e != nil {
		return a, e
	}
	for name, target := range map[string]*int{"cloud8021x-events": &a.EventsGID, "cloud8021x-spool-metadata": &a.SpoolGID} {
		g, e := user.LookupGroup(name)
		if e != nil {
			return a, errors.New("event-only group unavailable")
		}
		*target, e = strconv.Atoi(g.Gid)
		if e != nil || *target <= 0 {
			return a, errors.New("invalid event-only group")
		}
	}
	if a.RuntimeUID == a.NativeUID || a.RuntimeUID == a.CollectorUID || a.NativeUID == a.CollectorUID || a.RuntimeGID == a.NativeGID || a.RuntimeGID == a.CollectorGID || a.NativeGID == a.CollectorGID || a.EventsGID == a.NativeGID || a.SpoolGID == a.NativeGID {
		return a, errors.New("dedicated account separation required")
	}
	return a, nil
}
func EnsureAccounts(ctx context.Context) (Accounts, error) {
	return ensureAccounts(ctx, transactionRoot)
}
func (t *Transaction) EnsureAccounts(ctx context.Context) (Accounts, error) {
	return ensureAccounts(ctx, t.directory)
}
func ensureAccounts(ctx context.Context, receiptDirectory string) (Accounts, error) {
	if os.Geteuid() != 0 {
		return Accounts{}, errors.New("account provisioning requires root")
	}
	for _, group := range []string{"dd-agent", "cloud8021x", "cloud8021x-events", "cloud8021x-spool-metadata"} {
		if _, e := execute(ctx, "/usr/sbin/groupadd", "--force", "--system", group); e != nil {
			return Accounts{}, e
		}
	}
	if _, e := user.Lookup("cloud8021x"); e != nil {
		if _, e = execute(ctx, "/usr/sbin/useradd", "--system", "--no-create-home", "--home-dir", "/nonexistent", "--shell", "/usr/sbin/nologin", "--gid", "cloud8021x", "cloud8021x"); e != nil {
			return Accounts{}, e
		}
	}
	if _, e := execute(ctx, "/usr/sbin/usermod", "--groups", "cloud8021x-events,cloud8021x-spool-metadata", "--shell", "/usr/sbin/nologin", "--lock", "cloud8021x"); e != nil {
		return Accounts{}, e
	}
	if _, e := execute(ctx, "/usr/sbin/usermod", "--append", "--groups", "cloud8021x-events", "freerad"); e != nil {
		return Accounts{}, e
	}
	if _, err := user.Lookup("dd-agent"); err != nil {
		if _, err = execute(ctx, "/usr/sbin/useradd", "--system", "--no-create-home", "--home-dir", "/nonexistent", "--shell", "/usr/sbin/nologin", "--gid", "dd-agent", "dd-agent"); err != nil {
			return Accounts{}, err
		}
	}
	a, e := ReadAccounts()
	if e != nil {
		return a, e
	}
	if e = migrateLegacyDirectory("/var/log/freeradius", a, receiptDirectory); e != nil {
		return a, e
	}
	collector, err := user.Lookup("dd-agent")
	if err != nil {
		return a, err
	}
	groups, err := collector.GroupIds()
	if err != nil {
		return a, err
	}
	for _, gid := range groups {
		if gid == strconv.Itoa(a.NativeGID) {
			if _, err = execute(ctx, "/usr/bin/gpasswd", "--delete", "dd-agent", "freerad"); err != nil {
				return a, err
			}
		}
	}
	for _, path := range []string{"/etc/datadog-agent", "/etc/datadog-agent/conf.d", "/etc/datadog-agent/conf.d/freeradius.d"} {
		if e = migrateLegacyDirectory(path, a, receiptDirectory); e != nil {
			return a, e
		}
		if e = protectedDirectory(path, 0, 0, 0755); e != nil {
			return a, e
		}
	}
	return a, PrepareDirectories(a)
}
func PrepareDirectories(a Accounts) error {
	for _, d := range []struct {
		path     string
		uid, gid int
		mode     uint32
	}{
		{"/opt/datadog-agent/run", a.CollectorUID, a.CollectorGID, 0700}, {"/etc/cloud-8021x", 0, 0, 0755}, {"/etc/cloud-8021x/sources", 0, 0, 0700},
		{"/etc/step-ca", 0, 0, 0700}, {"/etc/step-ca-rsa", 0, 0, 0700},
		{"/run/cloud-8021x", 0, 0, 0755}, {"/run/cloud-8021x/database-pools", 0, a.RuntimeGID, 0750}, {"/run/cloud-8021x/credentials", a.RuntimeUID, a.RuntimeGID, 0700},
		{"/run/cloud-8021x-root", 0, 0, 0700}, {"/run/cloud-8021x-collector", a.CollectorUID, a.CollectorGID, 0700},
		{"/run/radius-verified-leaves", a.NativeUID, a.NativeGID, 0700}, {"/run/radius-certificate-bindings", a.RuntimeUID, a.RuntimeGID, 0700},
		{"/run/freeradius", a.NativeUID, a.NativeGID, 0755}, {"/var/lib/cloud-8021x", a.RuntimeUID, a.RuntimeGID, 0700},
		{"/var/cache/cloud-8021x", 0, 0, 0755}, {"/var/cache/cloud-8021x/runtime", a.RuntimeUID, a.RuntimeGID, 0700},
		{"/var/log/freeradius", 0, a.NativeGID, 0755}, {"/var/log/freeradius/auth", a.NativeUID, a.EventsGID, 02750},
		{"/var/log/freeradius/radacct", a.NativeUID, a.SpoolGID, 02750},
		{"/var/lib/cloud-8021x-source-proof", 0, 0, 0755}, {"/var/lib/cloud-8021x-source-state", 0, 0, 0755},
		{"/etc/systemd/system/freeradius.service.d", 0, 0, 0755},
	} {
		if e := protectedDirectory(d.path, d.uid, d.gid, d.mode); e != nil {
			return e
		}
	}
	for _, class := range []string{"accounting", "export", "auth", "certificates", "observation"} {
		path := "/run/cloud-8021x/database-pools/" + class + ".lock"
		fd, err := unix.Open(path, unix.O_RDWR|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0660)
		if err == nil {
			err = unix.Fchown(fd, 0, a.RuntimeGID)
			if err == nil {
				err = unix.Fchmod(fd, 0660)
			}
			_ = unix.Close(fd)
			if err != nil {
				return err
			}
		} else if !errors.Is(err, unix.EEXIST) {
			return err
		}
		var st unix.Stat_t
		if unix.Lstat(path, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 || st.Uid != 0 || int(st.Gid) != a.RuntimeGID || st.Mode&0777 != 0660 {
			return errors.New("runtime database pool slot identity differs")
		}
	}

	return nil
}
