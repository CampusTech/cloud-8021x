package host

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"

	"github.com/CampusTech/cloud-8021x/internal/domain"
)

type operatorAttempt struct {
	RequestID, RequestSHA256 string
	BinarySHA256             string
	Original                 json.RawMessage
	Attempt                  int64
	Helper                   writerPID
}

func operatorAttemptPath(id, hash string, attempt int64) (string, error) {
	valid := regexp.MustCompile(`^[0-9a-f]{64}$`)
	if !valid.MatchString(id) || !valid.MatchString(hash) || attempt < 1 {
		return "", errors.New("invalid original operator identity")
	}
	return filepath.Join(transactionRoot, "operator-attempts", id+".json"), nil
}

// The caller holds the fixed writer-operation flock throughout preparation,
// PostgreSQL start, bounded external call, and completion.
func PrepareOperatorAttempt(id, hash string, attempt int64, original []byte) error {
	if len(original) == 0 || len(original) > 2<<20 || !json.Valid(original) {
		return errors.New("invalid original operator work")
	}
	if os.Geteuid() != 0 {
		return errors.New("root operator helper required")
	}
	path, e := operatorAttemptPath(id, hash, attempt)
	if e != nil {
		return e
	}
	if e = protectedDirectory(filepath.Dir(path), 0, 0, 0700); e != nil {
		return e
	}
	if _, e = readPrivateCache(path, 3<<20); !errors.Is(e, os.ErrNotExist) {
		return errors.New("original operator helper already retained or unavailable")
	}
	executable, e := os.Executable()
	if e != nil {
		return e
	}
	binary, e := installedHash(executable, 256<<20)
	if e != nil {
		return e
	}
	record := operatorAttempt{RequestID: id, RequestSHA256: hash, Attempt: attempt, Original: append([]byte(nil), original...), BinarySHA256: binary}
	processes, e := scanWriterProcesses()
	if e != nil {
		return e
	}
	for _, p := range processes {
		if p.PID == os.Getpid() {
			record.Helper = writerPID{p.PID, p.Start}
		}
	}
	if record.Helper.Start == 0 {
		return errors.New("original helper identity unavailable")
	}
	raw, e := json.Marshal(record)
	if e != nil {
		return e
	}
	if e = privateWrite(path, raw, 0600); e != nil {
		return e
	}
	return syncWriterDirectory(filepath.Dir(path))
}
func ProveOperatorAttemptStopped(id, hash string, attempt int64) ([]byte, error) {
	if os.Geteuid() != 0 {
		return nil, errors.New("root operator helper proof required")
	}
	path, e := operatorAttemptPath(id, hash, attempt)
	if e != nil {
		return nil, e
	}
	raw, e := readPrivateCache(path, 3<<20)
	if e != nil {
		return nil, e
	}
	var original operatorAttempt
	if domain.DecodeJSONStrict(raw, &original) != nil || original.RequestID != id || original.RequestSHA256 != hash || original.Attempt != attempt || original.Helper.PID < 1 || original.Helper.Start == 0 {
		return nil, errors.New("original operator helper differs")
	}
	executable, e := os.Executable()
	if e != nil {
		return nil, e
	}
	binary, e := installedHash(executable, 256<<20)
	if e != nil || binary != original.BinarySHA256 || !json.Valid(original.Original) {
		return nil, errors.New("original binary/work differs")
	}
	processes, e := scanWriterProcesses()
	if e != nil {
		return nil, e
	}
	for _, p := range processes {
		if p.PID == original.Helper.PID && p.Start == original.Helper.Start {
			return nil, errors.New("original operator helper still active")
		}
	}
	return original.Original, nil
}
