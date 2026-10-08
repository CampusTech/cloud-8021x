package host

import (
	"bytes"
	"errors"
)

const legacyClassKey = "/run/radius-accounting-key"

func legacyClassSnapshot() (SavedFile, error) {
	uid, _, err := identity("freerad")
	if err != nil {
		uid = 0
	}
	appUID, _, appErr := identity("cloud8021x")
	if appErr != nil {
		appUID = 0
	}
	old, err := Snapshot(File{Path: legacyClassKey, UID: uid, adoptUID: appUID})
	if err != nil {
		return old, err
	}
	if old.Exists && (old.Mode != 0600 || len(old.Data) < 32 || len(old.Data) > 4096) {
		return old, errors.New("legacy Class key identity rejected")
	}
	return old, nil
}

// CheckLegacyClassKey is read-only and runs before package/native mutation.
// Missing legacy state permits initial setup; an existing key must match exactly.
func CheckLegacyClassKey(candidate []byte) error {
	old, err := legacyClassSnapshot()
	if err != nil {
		return err
	}
	if len(candidate) < 32 || len(candidate) > 4096 {
		return errors.New("shared Class key length rejected")
	}
	if old.Exists && !bytes.Equal(old.Data, candidate) {
		return errors.New("legacy shared Class key differs; explicit key migration required")
	}
	return nil
}

// Preserve the fixed legacy file for import/manual rollback, but remove native
// read access once the new daemon owns Class signing/verification. The transaction
// snapshots its original owner and bytes before publication.
func AdoptLegacyClassKey(candidate []byte, a Accounts) ([]File, error) {
	if err := CheckLegacyClassKey(candidate); err != nil {
		return nil, err
	}
	old, err := legacyClassSnapshot()
	if err != nil || !old.Exists {
		return nil, err
	}
	return []File{{Path: legacyClassKey, Data: old.Data, UID: a.RuntimeUID, GID: a.RuntimeGID, Mode: 0600, adoptUID: a.NativeUID}}, nil
}
