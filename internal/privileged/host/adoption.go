package host

import (
	"bytes"
	"errors"

	"github.com/CampusTech/cloud-8021x/internal/domain"
)

const legacyPolicySnapshot = "/etc/freeradius/3.0/device-policy-cache.json"
const daemonPolicySnapshot = "/var/lib/cloud-8021x/inventory.json"
const legacyDowngradeGuard = "/var/lib/cloud-8021x/fingerprint-enforced"

func validateAdoptionSnapshot(data []byte, mode string, guard bool) ([]byte, error) {
	if mode != "fingerprint" && mode != "legacy-serial" {
		return nil, errors.New("unsupported adoption identity mode")
	}
	if guard && mode != "fingerprint" {
		return nil, errors.New("sticky legacy fingerprint guard prevents downgrade")
	}
	snapshot, err := domain.DecodeSnapshot(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	if mode == "fingerprint" && snapshot.Version != 2 {
		return nil, errors.New("fingerprint adoption requires original certificate inventory")
	}
	return bytes.Clone(data), nil
}

// AdoptionSnapshotFile is part of the existing installation transaction, so
// activation failure restores prior bytes/absence. Never overwrite different
// pre-existing daemon policy state or give runtime access to native directories.
func AdoptionSnapshotFile(data []byte, a Accounts) ([]File, error) {
	if len(data) == 0 {
		return nil, nil
	}
	file := File{Path: daemonPolicySnapshot, Data: bytes.Clone(data), UID: a.RuntimeUID, GID: a.RuntimeGID, Mode: 0644}
	old, err := Snapshot(file)
	if err != nil {
		return nil, err
	}
	if old.Exists && !bytes.Equal(old.Data, data) {
		return nil, errors.New("different daemon policy already exists")
	}
	return []File{file}, nil
}
