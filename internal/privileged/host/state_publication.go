package host

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"

	"github.com/CampusTech/cloud-8021x/internal/domain"
	"github.com/CampusTech/cloud-8021x/internal/migration"
)

type StatePublication struct {
	Transition, Node, ConfigSHA256, BundleSHA256 string
	Attempt                                      int64
	Helper                                       writerPID
}

func publicationDirectory(p StatePublication) (string, error) {
	if p.Attempt <= 0 || !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(p.ConfigSHA256) || !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(p.BundleSHA256) || (p.Node != "radius-primary" && p.Node != "radius-secondary") {
		return "", errors.New("invalid exact publication identity")
	}
	return writerReceiptDirectory(p.Transition)
}
func publicationOriginal(p StatePublication) (StatePublication, []byte, error) {
	dir, e := publicationDirectory(p)
	if e != nil {
		return p, nil, e
	}
	raw, e := readPrivateCache(filepath.Join(dir, "publication-original.json"), 4096)
	if e != nil {
		return p, nil, e
	}
	var saved StatePublication
	if domain.DecodeJSONStrict(raw, &saved) != nil || saved.Transition != p.Transition || saved.Node != p.Node || saved.ConfigSHA256 != p.ConfigSHA256 || saved.BundleSHA256 != p.BundleSHA256 || saved.Attempt != p.Attempt || saved.Helper.PID <= 0 || saved.Helper.Start == 0 {
		return p, nil, errors.New("original publication identity differs")
	}
	return saved, raw, nil
}
func validatePublicationFiles(p StatePublication, data []byte) error {
	dir, e := publicationDirectory(p)
	if e != nil {
		return e
	}
	b, e := migration.DecodeBundle(data)
	if e != nil || b.Node != p.Node || digestBytes(data) != p.BundleSHA256 {
		return errors.New("original bundle changed")
	}
	published, e := readPrivateCache(filepath.Join(dir, "published-bundle.json"), 96<<20)
	if e != nil && !errors.Is(e, os.ErrNotExist) {
		return e
	}
	present := e == nil
	if present && !bytes.Equal(published, data) {
		return errors.New("local published bundle differs")
	}
	complete, e := readPrivateCache(filepath.Join(dir, "publication-complete.json"), 4096)
	if e == nil {
		_, original, e := publicationOriginal(p)
		if e != nil || !present || !bytes.Equal(complete, original) {
			return errors.New("publication receipt does not prove original bundle")
		}
		return nil
	}
	if !errors.Is(e, os.ErrNotExist) {
		return e
	}
	accounts, e := ReadAccounts()
	if e != nil {
		return e
	}
	snapshot, e := snapshotState(File{Path: daemonPolicySnapshot, UID: accounts.RuntimeUID})
	if e != nil {
		return e
	}
	if !snapshot.Exists || !bytes.Equal(snapshot.Data, b.Policy) {
		return errors.New("local authorization snapshot differs from original staged state")
	}
	guard, e := snapshotState(File{Path: legacyDowngradeGuard, UID: accounts.RuntimeUID})
	if e != nil {
		return e
	}
	if guard.Exists != b.FingerprintEnforced {
		return errors.New("local sticky fingerprint evidence differs")
	}
	return nil
}

// PrepareStatePublication writes one immutable original helper identity before
// importing SQL. The caller holds the fixed nonblocking writer operation lock.
func PrepareStatePublication(p StatePublication, data []byte) error {
	if os.Geteuid() != 0 {
		return errors.New("root publication required")
	}
	if e := validatePublicationFiles(p, data); e != nil {
		return e
	}
	dir, e := publicationDirectory(p)
	if e != nil {
		return e
	}
	if _, _, e = publicationOriginal(p); e == nil {
		return nil
	} else if !errors.Is(e, os.ErrNotExist) {
		return e
	}
	processes, e := scanWriterProcesses()
	if e != nil {
		return e
	}
	for _, process := range processes {
		if process.PID == os.Getpid() {
			p.Helper = writerPID{process.PID, process.Start}
		}
	}
	if p.Helper.Start == 0 {
		return errors.New("publication helper identity unavailable")
	}
	raw, e := json.Marshal(p)
	if e != nil {
		return e
	}
	if e = privateWrite(filepath.Join(dir, "publication-original.json"), raw, 0600); e != nil {
		return e
	}
	return syncWriterDirectory(dir)
}
func ValidateStatePublicationRecovery(p StatePublication, data []byte) error {
	if os.Geteuid() != 0 {
		return errors.New("root publication recovery required")
	}
	original, _, e := publicationOriginal(p)
	if e != nil {
		return e
	}
	processes, e := scanWriterProcesses()
	if e != nil {
		return e
	}
	for _, process := range processes {
		if process.PID == original.Helper.PID && process.Start == original.Helper.Start {
			return errors.New("original publication helper still active")
		}
	}
	return validatePublicationFiles(p, data)
}
func PublishCapturedState(p StatePublication, data []byte) error {
	if os.Geteuid() != 0 {
		return errors.New("root publication required")
	}
	_, original, e := publicationOriginal(p)
	if e != nil {
		return e
	}
	if e = validatePublicationFiles(p, data); e != nil {
		return e
	}
	dir, e := publicationDirectory(p)
	if e != nil {
		return e
	}
	if _, e = readPrivateCache(filepath.Join(dir, "published-bundle.json"), 96<<20); errors.Is(e, os.ErrNotExist) {
		if e = privateWrite(filepath.Join(dir, "published-bundle.json"), data, 0600); e != nil {
			return e
		}
	} else if e != nil {
		return e
	}
	if e = syncWriterDirectory(dir); e != nil {
		return e
	}
	if _, e = readPrivateCache(filepath.Join(dir, "publication-complete.json"), 4096); errors.Is(e, os.ErrNotExist) {
		if e = privateWrite(filepath.Join(dir, "publication-complete.json"), original, 0600); e != nil {
			return e
		}
	} else if e != nil {
		return e
	}
	return syncWriterDirectory(dir)
}
