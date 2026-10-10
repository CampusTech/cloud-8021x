package host

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// Only Debian's two known native-owned parents can be migrated. Their original
// metadata is durably retained outside the native account's reach before the
// ownership change. Contents, including accounting spools, are never removed.
// The complete config tree is independently retained by Transaction.Apply.
func migrateLegacyDirectory(path string, a Accounts, receiptDirectories ...string) error {
	receiptDirectory := transactionRoot
	if len(receiptDirectories) > 0 {
		receiptDirectory = receiptDirectories[0]
	}
	if receiptDirectory != transactionRoot && (filepath.Dir(receiptDirectory) != transactionRoot || !regexp.MustCompile(`^[0-9a-f]{32}$`).MatchString(filepath.Base(receiptDirectory))) {
		return errors.New("invalid legacy migration receipt")
	}
	name := ""
	expectedUID, expectedGID := a.NativeUID, a.NativeGID
	switch path {
	case radiusParent:
		name = "legacy-radius-parent.json"
	case "/var/log/freeradius":
		name = "legacy-log-parent.json"
	case "/etc/datadog-agent", "/etc/datadog-agent/conf.d", "/etc/datadog-agent/conf.d/freeradius.d":
		name = "legacy-collector-" + strings.ReplaceAll(strings.TrimPrefix(path, "/etc/"), "/", "-") + ".json"
		expectedUID, expectedGID = a.CollectorUID, a.CollectorGID
	default:
		return errors.New("unapproved legacy directory")
	}
	if os.Geteuid() != 0 {
		return errors.New("legacy migration requires root")
	}
	parent, err := unix.Open(filepath.Dir(path), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(parent) }()
	var pst unix.Stat_t
	if unix.Fstat(parent, &pst) != nil || pst.Uid != 0 || pst.Mode&0022 != 0 {
		return errors.New("unsafe legacy directory parent")
	}
	fd, err := unix.Openat(parent, filepath.Base(path), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil {
		return errors.New("unsafe legacy directory")
	}
	defer func() { _ = unix.Close(fd) }()
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Mode&0022 != 0 {
		return errors.New("unsafe legacy directory permissions")
	}
	if st.Uid == 0 {
		return nil
	}
	allowedGroup := int(st.Gid) == expectedGID
	if path == "/var/log/freeradius" {
		if group, err := user.LookupGroup("adm"); err == nil {
			gid, err := strconv.Atoi(group.Gid)
			allowedGroup = allowedGroup || (err == nil && int(st.Gid) == gid)
		}
	}
	if int(st.Uid) != expectedUID || !allowedGroup {
		return errors.New("unrecognized legacy directory owner")
	}
	if err = protectedDirectory(transactionRoot, 0, 0, 0700); err != nil {
		return err
	}
	data, err := json.Marshal(struct {
		Path           string
		UID, GID, Mode uint32
	}{path, st.Uid, st.Gid, uint32(st.Mode) & 07777})
	if err != nil {
		return err
	}
	receipt := filepath.Join(receiptDirectory, name)
	// An existing record with a still-unmigrated parent indicates interruption or
	// external reversal. Do not overwrite that evidence or automatically retry.
	if err = privateWrite(receipt, data, 0600); err != nil {
		return errors.New("legacy migration record exists or cannot be persisted; reconcile before retry")
	}
	directory, err := unix.Open(receiptDirectory, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	err = unix.Fsync(directory)
	_ = unix.Close(directory)
	if err != nil {
		return err
	}
	if err = unix.Fchown(fd, 0, expectedGID); err != nil {
		return err
	}
	if err = unix.Fchmod(fd, 0755); err != nil {
		return err
	}
	return unix.Fsync(fd)
}

// Restore only this transaction's recorded fixed parents, deepest first. Child
// files and accounting/collector data are never deleted or recursively chowned.
func (t *Transaction) restoreLegacyOwnership() error {
	entries := [][2]string{{"legacy-collector-datadog-agent-conf.d-freeradius.d.json", "/etc/datadog-agent/conf.d/freeradius.d"}, {"legacy-collector-datadog-agent-conf.d.json", "/etc/datadog-agent/conf.d"}, {"legacy-collector-datadog-agent.json", "/etc/datadog-agent"}, {"legacy-log-parent.json", "/var/log/freeradius"}, {"legacy-radius-parent.json", radiusParent}}
	for _, entry := range entries {
		data, err := readPrivateCache(filepath.Join(t.directory, entry[0]), 4096)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		var old struct {
			Path           string
			UID, GID, Mode uint32
		}
		d := json.NewDecoder(strings.NewReader(string(data)))
		d.DisallowUnknownFields()
		if d.Decode(&old) != nil || d.Decode(new(any)) != io.EOF || old.Path != entry[1] || old.UID == 0 || old.Mode&0022 != 0 || old.Mode > 07777 {
			return errors.New("legacy ownership receipt rejected")
		}
		fd, err := unix.Open(old.Path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			return err
		}
		var st unix.Stat_t
		if unix.Fstat(fd, &st) != nil || (st.Uid != 0 && st.Uid != old.UID) || st.Mode&0022 != 0 {
			_ = unix.Close(fd)
			return errors.New("legacy rollback directory changed")
		}
		err = unix.Fchown(fd, int(old.UID), int(old.GID))
		if err == nil {
			err = unix.Fchmod(fd, old.Mode)
		}
		if err == nil {
			err = unix.Fsync(fd)
		}
		_ = unix.Close(fd)
		if err != nil {
			return err
		}
	}
	return nil
}
