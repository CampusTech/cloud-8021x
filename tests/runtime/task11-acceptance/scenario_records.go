package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/adoption"
	sc "github.com/CampusTech/cloud-8021x/tests/runtime/task11-acceptance/scenariocontract"
	"golang.org/x/sys/unix"
)

var scenarioRecordDirs = []string{"requests", "results", "failures", "claims", "ca-selections"}
var scenarioRecordName = regexp.MustCompile(`^task11-[0-9a-f]{32}-([1-9]|1[0-9]|2[0-4])\.json$`)
var errScenarioRecord = errors.New("protected scenario record state unavailable or uncertain")

type scenarioRecords struct {
	mu                  sync.Mutex
	root                string
	uid, parent, rootFD int
	dirs                map[string]int
	closed              bool
}
type scenarioRecordHashes struct{ request, result string }
type scenarioClaim struct {
	Request       sc.Request
	RequestRaw    []byte
	RequestSHA256 string
	History       []sc.Completion

	store         *scenarioRecords
	request       sc.Request
	raw           []byte
	sha, name     string
	historyHashes []scenarioRecordHashes
	historyEnd    time.Time
	done          bool
}

// The only production entry has no path/owner selector. The internal constructor
// permits owned unit fixtures; it is never exposed through CLI or wire input.
func openScenarioRecords() (*scenarioRecords, error) {
	if os.Geteuid() != 0 {
		return nil, errScenarioRecord
	}
	return openScenarioRecordsAt(control+"/scenarios", 0)
}
func scenarioDirectory(fd, uid int) error {
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFDIR || int(st.Uid) != uid || st.Mode&07777 != 0700 {
		return errScenarioRecord
	}
	return nil
}
func scenarioSameInode(a, b *unix.Stat_t) bool { return a.Dev == b.Dev && a.Ino == b.Ino }
func openScenarioRecordsAt(root string, uid int) (*scenarioRecords, error) {
	if uid < 0 || !filepath.IsAbs(root) || filepath.Clean(root) != root || root == "/" || len(root) > 4096 {
		return nil, errScenarioRecord
	}
	parent, err := privateParent(root, uid)
	if err != nil {
		return nil, errScenarioRecord
	}
	s := &scenarioRecords{root: root, uid: uid, parent: parent, rootFD: -1, dirs: map[string]int{}}
	bad := func() (*scenarioRecords, error) { _ = s.Close(); return nil, errScenarioRecord }
	created := false
	if err = unix.Mkdirat(parent, filepath.Base(root), 0700); err == nil {
		created = true
	} else if !errors.Is(err, unix.EEXIST) {
		return bad()
	}
	s.rootFD, err = unix.Openat(parent, filepath.Base(root), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil || scenarioDirectory(s.rootFD, uid) != nil {
		return bad()
	}
	if created && unix.Fsync(parent) != nil {
		return bad()
	}
	for _, dir := range scenarioRecordDirs {
		created = false
		if err = unix.Mkdirat(s.rootFD, dir, 0700); err == nil {
			created = true
		} else if !errors.Is(err, unix.EEXIST) {
			return bad()
		}
		fd, e := unix.Openat(s.rootFD, dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if e != nil {
			return bad()
		}
		s.dirs[dir] = fd
		if scenarioDirectory(fd, uid) != nil || (created && unix.Fsync(s.rootFD) != nil) {
			return bad()
		}
	}
	if s.checkBinding() != nil {
		return bad()
	}
	return s, nil
}
func (s *scenarioRecords) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	var failure bool
	for _, fd := range s.dirs {
		if unix.Close(fd) != nil {
			failure = true
		}
	}
	if s.rootFD >= 0 && unix.Close(s.rootFD) != nil {
		failure = true
	}
	if s.parent >= 0 && unix.Close(s.parent) != nil {
		failure = true
	}
	if failure {
		return errScenarioRecord
	}
	return nil
}
func (s *scenarioRecords) checkBinding() error {
	if s.closed || scenarioDirectory(s.rootFD, s.uid) != nil {
		return errScenarioRecord
	}
	current, err := privateParent(s.root, s.uid)
	if err != nil {
		return errScenarioRecord
	}
	defer func() { _ = unix.Close(current) }()
	var held, now unix.Stat_t
	if unix.Fstat(s.parent, &held) != nil || unix.Fstat(current, &now) != nil || !scenarioSameInode(&held, &now) {
		return errScenarioRecord
	}
	if unix.Fstat(s.rootFD, &held) != nil || unix.Fstatat(s.parent, filepath.Base(s.root), &now, unix.AT_SYMLINK_NOFOLLOW) != nil || now.Mode&unix.S_IFMT != unix.S_IFDIR || !scenarioSameInode(&held, &now) {
		return errScenarioRecord
	}
	for _, name := range scenarioRecordDirs {
		fd, ok := s.dirs[name]
		if !ok || scenarioDirectory(fd, s.uid) != nil || unix.Fstat(fd, &held) != nil || unix.Fstatat(s.rootFD, name, &now, unix.AT_SYMLINK_NOFOLLOW) != nil || now.Mode&unix.S_IFMT != unix.S_IFDIR || !scenarioSameInode(&held, &now) {
			return errScenarioRecord
		}
	}
	return nil
}
func scenarioRecordFile(fd, uid, limit int) (unix.Stat_t, error) {
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || int(st.Uid) != uid || st.Mode&07777 != 0600 || st.Nlink != 1 || st.Size < 0 || st.Size > int64(limit) {
		return st, errScenarioRecord
	}
	return st, nil
}
func (s *scenarioRecords) read(dir, name string, limit int) ([]byte, error) {
	if !scenarioRecordName.MatchString(name) || s.checkBinding() != nil {
		return nil, errScenarioRecord
	}
	fd, err := unix.Openat(s.dirs[dir], name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, errScenarioRecord
	}
	f := os.NewFile(uintptr(fd), "protected-scenario-record")
	defer func() { _ = f.Close() }()
	before, err := scenarioRecordFile(fd, s.uid, limit)
	info, infoErr := f.Stat()
	if err != nil || infoErr != nil {
		return nil, errScenarioRecord
	}
	raw, err := io.ReadAll(io.LimitReader(f, int64(limit)+1))
	after, statErr := scenarioRecordFile(fd, s.uid, limit)
	final, finalErr := f.Stat()
	if err != nil || statErr != nil || finalErr != nil || len(raw) > limit || int64(len(raw)) != before.Size || !scenarioSameInode(&before, &after) || before.Mode != after.Mode || before.Uid != after.Uid || before.Gid != after.Gid || before.Nlink != after.Nlink || before.Size != after.Size || !info.ModTime().Equal(final.ModTime()) || s.checkBinding() != nil {
		clear(raw)
		return nil, errScenarioRecord
	}
	return raw, nil
}
func (s *scenarioRecords) exists(dir, name string) (bool, error) {
	var st unix.Stat_t
	err := unix.Fstatat(s.dirs[dir], name, &st, unix.AT_SYMLINK_NOFOLLOW)
	if errors.Is(err, unix.ENOENT) {
		return false, nil
	}
	if err != nil {
		return false, errScenarioRecord
	}
	return true, nil
}
func (s *scenarioRecords) canonicalEntries(dir string) error {
	// A fresh directory description avoids sharing/reusing a read cursor. A
	// bounded listing also refuses retained noncanonical aliases such as -01.
	fd, err := unix.Openat(s.dirs[dir], ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return errScenarioRecord
	}
	f := os.NewFile(uintptr(fd), "protected-scenario-directory")
	defer func() { _ = f.Close() }()
	names, err := f.Readdirnames(4097)
	if (err != nil && !errors.Is(err, io.EOF)) || len(names) > 4096 {
		return errScenarioRecord
	}
	for _, name := range names {
		if !scenarioRecordName.MatchString(name) {
			return errScenarioRecord
		}
	}
	return nil
}
func (s *scenarioRecords) uncertainty(r sc.Request, ownClaim bool) error {
	if s.checkBinding() != nil {
		return errScenarioRecord
	}
	for _, dir := range []string{"claims", "results", "failures"} {
		if s.canonicalEntries(dir) != nil {
			return errScenarioRecord
		}
		for sequence := r.Sequence; sequence <= sc.MaxSequence; sequence++ {
			name := fmt.Sprintf("%s-%d.json", r.AttemptID, sequence)
			exists, err := s.exists(dir, name)
			if err != nil {
				return err
			}
			if ownClaim && dir == "claims" && sequence == r.Sequence {
				if !exists {
					return errScenarioRecord
				}
			} else if exists {
				return errScenarioRecord
			}
		}
	}
	return nil
}
func (s *scenarioRecords) history(r sc.Request) ([]sc.Completion, []scenarioRecordHashes, error) {
	var history []sc.Completion
	var hashes []scenarioRecordHashes
	for sequence := 1; sequence < r.Sequence; sequence++ {
		name := fmt.Sprintf("%s-%d.json", r.AttemptID, sequence)
		failed, err := s.exists("failures", name)
		if err != nil || failed {
			return nil, nil, errScenarioRecord
		}
		raw, err := s.read("requests", name, sc.MaxRequestBytes)
		if err != nil {
			return nil, nil, err
		}
		claimed, err := s.read("claims", name, sc.MaxRequestBytes)
		if err != nil || !bytes.Equal(raw, claimed) {
			clear(raw)
			clear(claimed)
			return nil, nil, errScenarioRecord
		}
		clear(claimed)
		previous, err := sc.DecodeRequest(raw)
		requestSHA := adoption.Digest(raw)
		clear(raw)
		if err != nil || previous.AttemptID != r.AttemptID || previous.Sequence != sequence {
			return nil, nil, errScenarioRecord
		}
		resultRaw, err := s.read("results", name, sc.MaxResultBytes)
		if err != nil {
			return nil, nil, err
		}
		result, err := sc.DecodeResult(resultRaw, previous, requestSHA)
		resultSHA := adoption.Digest(resultRaw)
		clear(resultRaw)
		if err != nil {
			return nil, nil, errScenarioRecord
		}
		history = append(history, sc.Completion{Request: previous, RequestSHA256: requestSHA, Result: result})
		hashes = append(hashes, scenarioRecordHashes{request: requestSHA, result: resultSHA})
	}
	if sc.ValidateHistory(r, history) != nil {
		return nil, nil, errScenarioRecord
	}
	return history, hashes, nil
}
func (s *scenarioRecords) publish(dir, name string, raw []byte, limit int) error {
	if len(raw) > limit || !scenarioRecordName.MatchString(name) || s.checkBinding() != nil {
		return errScenarioRecord
	}
	fd, err := unix.Openat(s.dirs[dir], name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return errScenarioRecord
	}
	// A partial file is intentionally retained as uncertain state. Never unlink,
	// replace, recover or retry an exclusive record on publication failure.
	f := os.NewFile(uintptr(fd), "exclusive-scenario-record")
	_, guardErr := scenarioRecordFile(fd, s.uid, limit)
	if guardErr == nil {
		_, err = io.Copy(f, bytes.NewReader(raw))
	} else {
		err = guardErr
	}
	if err == nil {
		err = f.Sync()
	}
	final, guardErr := scenarioRecordFile(fd, s.uid, limit)
	closeErr := f.Close()
	dirSyncErr := unix.Fsync(s.dirs[dir])
	bindingErr := s.checkBinding()
	if err != nil || guardErr != nil || final.Size != int64(len(raw)) || closeErr != nil || dirSyncErr != nil || bindingErr != nil {
		return errScenarioRecord
	}
	return nil
}
func (s *scenarioRecords) Admit(stage sc.Stage, pins sc.Pins) (*scenarioClaim, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	stageRaw, err := json.Marshal(stage)
	decoded, stageErr := sc.DecodeStage(stageRaw)
	if err != nil || stageErr != nil || decoded.Stage != "scenario-operation" {
		return nil, errScenarioRecord
	}
	name := fmt.Sprintf("%s-%d.json", stage.AttemptID, stage.Sequence)
	raw, err := s.read("requests", name, sc.MaxRequestBytes)
	if err != nil {
		return nil, err
	}
	r, err := sc.DecodeRequest(raw)
	if err != nil || r.AttemptID != stage.AttemptID || r.Sequence != stage.Sequence || r.Pins != pins || adoption.Digest(raw) != stage.RequestSHA256 || s.uncertainty(r, false) != nil {
		clear(raw)
		return nil, errScenarioRecord
	}
	history, hashes, err := s.history(r)
	if err != nil {
		clear(raw)
		return nil, err
	}
	if err := s.publish("claims", name, raw, sc.MaxRequestBytes); err != nil {
		clear(raw)
		return nil, err
	}
	public := r
	public.Sessions = append([]string(nil), r.Sessions...)
	c := &scenarioClaim{Request: public, RequestRaw: bytes.Clone(raw), RequestSHA256: stage.RequestSHA256, History: history, store: s, request: r, raw: raw, sha: stage.RequestSHA256, name: name, historyHashes: hashes}
	if len(history) != 0 {
		c.historyEnd = history[len(history)-1].Result.FinishedAt
	}
	if _, err := c.recheck(); err != nil {
		clear(raw)
		return nil, err
	}
	return c, nil
}
func (c *scenarioClaim) recheck() ([]sc.Completion, error) {
	if c.done || c.store.uncertainty(c.request, true) != nil {
		return nil, errScenarioRecord
	}
	current, err := c.store.read("requests", c.name, sc.MaxRequestBytes)
	if err != nil {
		return nil, err
	}
	claim, err := c.store.read("claims", c.name, sc.MaxRequestBytes)
	ok := err == nil && bytes.Equal(current, c.raw) && bytes.Equal(claim, c.raw)
	clear(current)
	clear(claim)
	if !ok {
		return nil, errScenarioRecord
	}
	history, hashes, err := c.store.history(c.request)
	if err != nil || len(hashes) != len(c.historyHashes) {
		return nil, errScenarioRecord
	}
	for i, hash := range hashes {
		if hash != c.historyHashes[i] {
			return nil, errScenarioRecord
		}
	}
	return history, nil
}
func (c *scenarioClaim) PublishResult(raw []byte) error {
	c.store.mu.Lock()
	defer c.store.mu.Unlock()
	if _, err := c.recheck(); err != nil {
		return err
	}
	result, err := sc.DecodeResult(raw, c.request, c.sha)
	if err != nil || (!c.historyEnd.IsZero() && result.StartedAt.Before(c.historyEnd)) {
		return errScenarioRecord
	}
	if err := c.store.publish("results", c.name, raw, sc.MaxResultBytes); err != nil {
		return err
	}
	c.done = true
	return nil
}
func (c *scenarioClaim) Fail(code string, uncertain bool) error {
	c.store.mu.Lock()
	defer c.store.mu.Unlock()
	switch code {
	case "operation-failed", "operation-uncertain", "retirement-failed", "publication-failed", "selection-failed":
	default:
		return errors.New("closed public scenario failure code required")
	}
	if _, err := c.recheck(); err != nil {
		return err
	}
	failure := struct {
		Schema        int    `json:"schema"`
		AttemptID     string `json:"attempt_id"`
		Sequence      int    `json:"sequence"`
		Action        string `json:"action"`
		RequestSHA256 string `json:"request_sha256"`
		Code          string `json:"code"`
		Uncertain     bool   `json:"uncertain"`
	}{1, c.request.AttemptID, c.request.Sequence, c.request.Action, c.sha, code, uncertain}
	raw, err := json.Marshal(failure)
	if err != nil {
		return errScenarioRecord
	}
	if err = c.store.publish("failures", c.name, raw, 4096); err != nil {
		return err
	}
	c.done = true
	return nil
}
func (c *scenarioClaim) ReadCASelection() ([]byte, sc.CASelection, error) {
	c.store.mu.Lock()
	defer c.store.mu.Unlock()
	var empty sc.CASelection
	r := c.request
	selected := r.Action == "read-ca-issued" || (r.Authority == "rsa" && (r.Action == "nas-ca-adopted" || r.Action == "nas-ca-passive"))
	if !selected {
		return nil, empty, errScenarioRecord
	}
	history, err := c.recheck()
	if err != nil || r.IssuanceSequence < 1 || r.IssuanceSequence > len(history) {
		return nil, empty, errScenarioRecord
	}
	name := fmt.Sprintf("%s-%d.json", r.AttemptID, r.IssuanceSequence)
	raw, err := c.store.read("ca-selections", name, sc.MaxRequestBytes)
	if err != nil {
		return nil, empty, err
	}
	selection, err := sc.DecodeCASelection(raw)
	prior := history[r.IssuanceSequence-1]
	previous := prior.Result
	if err != nil || adoption.Digest(raw) != r.SelectionSHA256 || selection.AttemptID != r.AttemptID || selection.IssuanceSequence != r.IssuanceSequence || selection.ResultSHA256 != c.historyHashes[r.IssuanceSequence-1].result || previous.CA == nil || previous.CA.Issued == nil {
		clear(raw)
		return nil, empty, errScenarioRecord
	}
	ca := previous.CA
	if r.Action != "read-ca-issued" && (prior.Request.Action != "nas-ca-original" || ca.Phase != "original") {
		clear(raw)
		return nil, empty, errScenarioRecord
	}
	leaf := ca.Issued
	if selection.Authority != ca.Authority || (r.Authority != "" && selection.Authority != r.Authority) || selection.Serial != leaf.Serial || selection.LeafDERSHA256 != leaf.LeafDERSHA256 || selection.OriginalRootSHA256 != ca.OriginalRootSHA256 || selection.OriginalIntermediateSHA256 != ca.OriginalIntermediateSHA256 {
		clear(raw)
		return nil, empty, errScenarioRecord
	}
	return raw, selection, nil
}
