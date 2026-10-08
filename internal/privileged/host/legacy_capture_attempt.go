package host

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/CampusTech/cloud-8021x/internal/domain"
	"github.com/CampusTech/cloud-8021x/internal/migration"
)

type legacyCaptureAttempt struct {
	Transition, Node, ConfigSHA256, WriterSHA256 string
	Attempt                                      int64
	Helper                                       writerPID
}
type legacyCaptureComplete struct {
	OriginalSHA256, SQLSHA256, BundleSHA256 string
}

// PrepareLegacyCaptureAttempt records only this fixed migration preparation.
// The caller holds the operation flock and a live legacy-capture gate.
func PrepareLegacyCaptureAttempt(id, node, hash, writer string, attempt int64) error {
	if os.Geteuid() != 0 || attempt < 1 {
		return errors.New("protected legacy capture attempt required")
	}
	dir, e := writerReceiptDirectory(id)
	if e != nil {
		return e
	}
	processes, e := scanWriterProcesses()
	if e != nil {
		return e
	}
	r := legacyCaptureAttempt{Transition: id, Node: node, ConfigSHA256: hash, WriterSHA256: writer, Attempt: attempt}
	for _, p := range processes {
		if p.PID == os.Getpid() {
			r.Helper = writerPID{p.PID, p.Start}
		}
	}
	if r.Helper.Start == 0 {
		return errors.New("legacy capture helper unavailable")
	}
	raw, e := json.Marshal(r)
	if e != nil {
		return e
	}
	path := filepath.Join(dir, fmt.Sprintf("legacy-capture-attempt-%d.json", attempt))
	if e = privateWrite(path, raw, 0600); e != nil {
		return e
	}
	return syncWriterDirectory(dir)
}
func readLegacyCaptureAttempt(id, node, hash, writer string, attempt int64) (legacyCaptureAttempt, []byte, error) {
	var r legacyCaptureAttempt
	dir, e := writerReceiptDirectory(id)
	if e != nil {
		return r, nil, e
	}
	raw, e := readPrivateCache(filepath.Join(dir, fmt.Sprintf("legacy-capture-attempt-%d.json", attempt)), 4096)
	if e != nil {
		return r, nil, e
	}
	if domain.DecodeJSONStrict(raw, &r) != nil || r.Transition != id || r.Node != node || r.ConfigSHA256 != hash || r.WriterSHA256 != writer || r.Attempt != attempt || r.Helper.PID < 1 || r.Helper.Start == 0 {
		return r, nil, errors.New("legacy capture original binding changed")
	}
	return r, raw, nil
}
func ProveLegacyCaptureStopped(id, node, hash, writer string, attempt int64) error {
	r, _, e := readLegacyCaptureAttempt(id, node, hash, writer, attempt)
	if e != nil {
		return e
	}
	processes, e := scanWriterProcesses()
	if e != nil {
		return e
	}
	for _, p := range processes {
		if p.PID == r.Helper.PID && p.Start == r.Helper.Start {
			return errors.New("original legacy capture helper alive")
		}
	}
	return nil
}
func CompleteLegacyCapture(id, node, hash, writer string, attempt int64, class []byte) error {
	_, original, e := readLegacyCaptureAttempt(id, node, hash, writer, attempt)
	if e != nil {
		return e
	}
	dir, e := writerReceiptDirectory(id)
	if e != nil {
		return e
	}
	sql, e := readPrivateCache(filepath.Join(dir, "legacy-sql.json"), 64<<20)
	if e != nil {
		return e
	}
	c, e := readLegacySQLCapture(id, node)
	if e != nil || c.ConfigSHA256 != hash || c.WriterSHA256 != writer {
		return errors.New("SQL capture completion differs")
	}
	bundle, e := ReadCapturedLegacyState(id, node, class)
	if e != nil {
		return e
	}
	b, e := migration.DecodeBundle(bundle)
	if e != nil {
		return e
	}
	actual, _ := json.Marshal(b.SQL)
	expected, _ := json.Marshal(c.SQL)
	if !bytes.Equal(actual, expected) {
		return errors.New("original bundle SQL differs from archive")
	}
	r := legacyCaptureComplete{digestBytes(original), digestBytes(sql), digestBytes(bundle)}
	raw, e := json.Marshal(r)
	if e != nil {
		return e
	}
	path := filepath.Join(dir, "legacy-capture-complete.json")
	if prior, e := readPrivateCache(path, 4096); e == nil {
		if !bytes.Equal(raw, prior) {
			return errors.New("legacy completion differs")
		}
		return nil
	} else if !errors.Is(e, os.ErrNotExist) {
		return e
	}
	if e = privateWrite(path, raw, 0600); e != nil {
		return e
	}
	return syncWriterDirectory(dir)
}

// LegacyCaptureRecorded never creates or repairs an archive. The original SQL
// plus full bundle are sufficient durable evidence if completion was interrupted.
func LegacyCaptureRecorded(id, node, hash, writer string, attempt int64, class []byte) (bool, error) {
	_, original, e := readLegacyCaptureAttempt(id, node, hash, writer, attempt)
	if e != nil {
		return false, e
	}
	dir, e := writerReceiptDirectory(id)
	if e != nil {
		return false, e
	}
	sql, se := readPrivateCache(filepath.Join(dir, "legacy-sql.json"), 64<<20)
	bundle, be := ReadCapturedLegacyState(id, node, class)
	complete, ce := readPrivateCache(filepath.Join(dir, "legacy-capture-complete.json"), 4096)
	if errors.Is(se, os.ErrNotExist) && errors.Is(be, os.ErrNotExist) && errors.Is(ce, os.ErrNotExist) {
		return false, nil
	}
	if se != nil || be != nil {
		return false, errors.New("partial legacy archive remains uncertain")
	}
	c, e := readLegacySQLCapture(id, node)
	if e != nil || c.ConfigSHA256 != hash || c.WriterSHA256 != writer {
		return false, errors.New("legacy SQL identity differs")
	}
	b, e := migration.DecodeBundle(bundle)
	if e != nil {
		return false, e
	}
	actual, _ := json.Marshal(b.SQL)
	expected, _ := json.Marshal(c.SQL)
	if !bytes.Equal(actual, expected) {
		return false, errors.New("bundle SQL differs from archive")
	}
	if ce == nil {
		var r legacyCaptureComplete
		if domain.DecodeJSONStrict(complete, &r) != nil || r.OriginalSHA256 != digestBytes(original) || r.SQLSHA256 != digestBytes(sql) || r.BundleSHA256 != digestBytes(bundle) {
			return false, errors.New("legacy completion proof differs")
		}
	} else if !errors.Is(ce, os.ErrNotExist) {
		return false, ce
	}
	return true, nil
}

func LegacyCaptureOriginalAttempt(id, node, hash, writer string) (int64, error) {
	dir, e := writerReceiptDirectory(id)
	if e != nil {
		return 0, e
	}
	// Only these immutable fixed preparation records are inspected. A bounded
	// count prevents an unbounded privileged recovery scan.
	fd, e := openParentDescriptor(filepath.Join(dir, "legacy-capture-original"), 0, false)
	if e != nil {
		return 0, e
	}
	directory := os.NewFile(uintptr(fd), "legacy-preparation-directory")
	defer func() { _ = directory.Close() }()
	entries, e := directory.ReadDir(513)
	if e != nil && !errors.Is(e, io.EOF) {
		return 0, e
	}
	if len(entries) > 512 {
		return 0, errors.New("legacy preparation archive bound exceeded")
	}
	var latest int64
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasPrefix(name, "legacy-capture-attempt-") || !strings.HasSuffix(name, ".json") {
			continue
		}
		value, e := strconv.ParseInt(strings.TrimSuffix(strings.TrimPrefix(name, "legacy-capture-attempt-"), ".json"), 10, 64)
		if e != nil || value < 1 {
			return 0, errors.New("invalid legacy capture archive name")
		}
		if _, _, e = readLegacyCaptureAttempt(id, node, hash, writer, value); e != nil {
			return 0, e
		}
		if value > latest {
			latest = value
		}
	}
	if latest == 0 {
		return 0, os.ErrNotExist
	}
	return latest, nil
}
