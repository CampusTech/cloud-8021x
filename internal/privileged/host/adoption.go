package host

import (
	"bytes"
	"errors"
	"os"

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

// ReadLegacyPolicySnapshot is root-only, fixed-path and called after local writer
// proof, before CA/package/tree replacement. It never repairs timestamps or reads
// any native private key. A successful Go installation uses its existing snapshot.
func ReadLegacyPolicySnapshot(mode string) ([]byte, error) {
	if os.Geteuid() != 0 {
		return nil, errors.New("root policy adoption required")
	}
	known, err := KnownInstallation()
	if err != nil {
		return nil, err
	}
	if known {
		return nil, nil
	}
	uid, _, err := identity("freerad")
	if err != nil {
		return nil, err
	}
	saved, err := Snapshot(File{Path: legacyPolicySnapshot, UID: uid})
	if err != nil {
		return nil, err
	}
	if !saved.Exists {
		return nil, errors.New("legacy policy snapshot absent; explicit initial state preparation required")
	}
	guard, err := rootFile(legacyDowngradeGuard, 4096)
	present := err == nil
	if present {
		_ = guard.Close()
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, errors.New("legacy identity guard unavailable")
	}
	return validateAdoptionSnapshot(saved.Data, mode, present)
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
