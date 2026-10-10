package host

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/CampusTech/cloud-8021x/internal/domain"
)

type sourceAttempt struct {
	Operation string
	Attempt   int64
	Helper    writerPID
}

func sourceAttemptPath(operation string, attempt int64) (string, error) {
	if !regexp.MustCompile(`^sources-apply:[0-9a-f]{64}$|^source-history:[0-9a-f]{64}$`).MatchString(operation) || attempt < 0 {
		return "", errors.New("invalid exact source operation")
	}
	parts := strings.Split(operation, ":")
	name := parts[0] + "-" + parts[1]
	if parts[0] == "source-history" {
		if attempt == 0 {
			return "", errors.New("original history attempt required")
		}
		name += fmt.Sprintf("-%d", attempt)
	}
	return filepath.Join(transactionRoot, "source-attempts", name+".json"), nil
}

// PrepareSourceAttempt runs under the fixed writer-operation flock, acquired
// before claiming source work, and before the original gated host action.
func PrepareSourceAttempt(operation string, attempt int64) error {
	if os.Geteuid() != 0 || attempt < 1 {
		return errors.New("protected original source attempt required")
	}
	path, e := sourceAttemptPath(operation, attempt)
	if e != nil {
		return e
	}
	if e = protectedDirectory(filepath.Dir(path), 0, 0, 0700); e != nil {
		return e
	}
	processes, e := scanWriterProcesses()
	if e != nil {
		return e
	}
	record := sourceAttempt{Operation: operation, Attempt: attempt}
	for _, p := range processes {
		if p.PID == os.Getpid() {
			record.Helper = writerPID{p.PID, p.Start}
		}
	}
	if record.Helper.Start == 0 {
		return errors.New("original source helper identity unavailable")
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
func ProveSourceAttemptStopped(operation string, attempt int64) error {
	if os.Geteuid() != 0 {
		return errors.New("root original source proof required")
	}
	path, e := sourceAttemptPath(operation, attempt)
	if e != nil {
		return e
	}
	raw, e := readPrivateCache(path, 4096)
	if e != nil {
		return e
	}
	var record sourceAttempt
	if domain.DecodeJSONStrict(raw, &record) != nil || record.Operation != operation || record.Attempt < 1 || attempt > 0 && record.Attempt != attempt || record.Helper.PID < 1 || record.Helper.Start == 0 {
		return errors.New("source original identity changed")
	}
	processes, e := scanWriterProcesses()
	if e != nil {
		return e
	}
	for _, p := range processes {
		if p.PID == record.Helper.PID && p.Start == record.Helper.Start {
			return errors.New("original source helper still alive")
		}
	}
	return nil
}
