package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

const fixedCloudRoot = "/var/lib/cloud8021x-task11/control/original-seed/api"
const stateLimit = 32 << 20

func digestBytes(data []byte) string { sum := sha256.Sum256(data); return hex.EncodeToString(sum[:]) }

type remoteEvent struct {
	PeerIP      string          `json:"peer_ip,omitempty"`
	PeerRole    string          `json:"peer_role,omitempty"`
	Observation json.RawMessage `json:"observation,omitempty"`
	Sequence    int             `json:"sequence"`
	Time        string          `json:"time"`
	Phase       string          `json:"phase"`
	Protocol    string          `json:"protocol"`
	Method      string          `json:"method"`
	Target      string          `json:"target"`
	BodyBytes   int             `json:"body_bytes"`
	BodySHA256  string          `json:"body_sha256"`
	Status      int             `json:"status"`
}

// Resolve each ancestor without following links, retaining a directory fd.
// Root-owned sticky ancestors permit the isolated test temp directory only;
// the final state directory remains private and owned by this process.
func privateParent(path string) (int, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return -1, errors.New("noncanonical private path")
	}
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	for _, part := range strings.Split(strings.TrimPrefix(filepath.Dir(path), "/"), "/") {
		if part == "" {
			continue
		}
		next, e := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		_ = unix.Close(fd)
		if e != nil {
			return -1, e
		}
		fd = next
		var st unix.Stat_t
		if e = unix.Fstat(fd, &st); e != nil || (int(st.Uid) != 0 && int(st.Uid) != os.Geteuid()) || (st.Mode&0022 != 0 && (st.Uid != 0 || st.Mode&unix.S_ISVTX == 0)) {
			_ = unix.Close(fd)
			return -1, errors.New("unsafe evidence directory")
		}
	}
	return fd, nil
}
func privateFile(path string, flags int) (*os.File, error) {
	parent, err := privateParent(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = unix.Close(parent) }()
	fd, err := unix.Openat(parent, filepath.Base(path), flags|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0600)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	info, err := file.Stat()
	var stat unix.Stat_t
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || unix.Fstat(fd, &stat) != nil || stat.Uid != uint32(os.Geteuid()) || stat.Nlink != 1 {
		_ = file.Close()
		return nil, errors.New("private fixture file ownership/mode rejected")
	}
	return file, nil
}
func privateRead(path string) ([]byte, error) {
	file, err := privateFile(path, unix.O_RDONLY)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	data, err := io.ReadAll(io.LimitReader(file, stateLimit+1))
	if err != nil || len(data) > stateLimit {
		return nil, errors.New("private fixture file exceeds bound")
	}
	return data, nil
}
func (f *fixture) openRemote() (func(), error) {
	f.initializeRemote()
	if f.incompleteEvidence {
		return nil, errors.New("transport evidence incomplete")
	}
	if f.stateRoot == "" || f.config.Contract == nil {
		return func() {}, nil
	}
	info, err := os.Lstat(f.stateRoot)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
		return nil, errors.New("fixture state root requires private real directory")
	}
	lock, err := privateFile(filepath.Join(f.stateRoot, "state.lock"), unix.O_CREAT|unix.O_RDWR)
	if err != nil {
		return nil, err
	}
	if err = unix.Flock(int(lock.Fd()), unix.LOCK_EX); err != nil {
		_ = lock.Close()
		return nil, err
	}
	release := func() { _ = unix.Flock(int(lock.Fd()), unix.LOCK_UN); _ = lock.Close() }
	if _, err := os.Lstat(filepath.Join(f.stateRoot, incompleteEvidenceFile)); !os.IsNotExist(err) {
		release()
		return nil, errors.New("persisted transport evidence incomplete")
	}
	data, err := privateRead(filepath.Join(f.stateRoot, "remote-state.json"))
	if err == nil {
		var state remoteState
		if strictJSON(data, &state) != nil || state.Schema != 1 || state.SeedSHA256 != f.remote.SeedSHA256 || state.Secrets == nil || state.Commands == nil {
			release()
			return nil, errors.New("persistent remote state binding rejected")
		}
		f.remote = &state
	} else if !os.IsNotExist(err) {
		release()
		return nil, err
	}
	journal, err := privateRead(filepath.Join(f.stateRoot, "journal.jsonl"))
	if err != nil && !os.IsNotExist(err) {
		release()
		return nil, err
	}
	if err = f.auditJournal(journal); err != nil {
		release()
		return nil, err
	}
	f.journalBytes = int64(len(journal))
	return release, nil
}
func (f *fixture) auditJournal(data []byte) error {
	if err := f.auditPeerHistory(false); err != nil {
		return err
	}
	var expected bytes.Buffer
	for i, event := range f.remote.Events {
		if event.Sequence != i+1 {
			return errors.New("journal sequence rejected")
		}
		raw, _ := json.Marshal(event)
		expected.Write(raw)
		expected.WriteByte('\n')
	}
	if !bytes.Equal(data, expected.Bytes()) {
		return errors.New("remote journal/state mismatch; uncertain operation requires investigation")
	}
	return nil
}
func (f *fixture) commitRemote() error {
	if f.stateRoot == "" || f.config.Contract == nil {
		return nil
	}
	data, err := json.Marshal(f.remote)
	if err != nil || len(data) > stateLimit {
		return errors.New("remote state bound exceeded")
	}
	parent, err := privateParent(filepath.Join(f.stateRoot, "remote-state.json"))
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(parent) }()
	var nonce [16]byte
	if _, err = rand.Read(nonce[:]); err != nil {
		return err
	}
	name := ".remote-state-" + hex.EncodeToString(nonce[:])
	fd, err := unix.Openat(parent, name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), name)
	defer func() { _ = unix.Unlinkat(parent, name, 0) }()
	if _, err = file.Write(data); err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err = unix.Renameat(parent, name, parent, "remote-state.json"); err != nil {
		return err
	}
	return unix.Fsync(parent)
}
func (f *fixture) recordRemote(protocol, method, target string, body []byte, code int) error {
	if len(f.remote.Events) >= 8192 || len(target) > 4096 {
		return errors.New("remote evidence bound reached")
	}
	event := remoteEvent{PeerIP: f.callerIP, PeerRole: f.callerRole, Observation: f.observation, Sequence: len(f.remote.Events) + 1, Time: time.Now().UTC().Format(time.RFC3339Nano), Phase: f.phase, Protocol: protocol, Method: method, Target: target, BodyBytes: len(body), BodySHA256: digestBytes(body), Status: code}
	entry, err := json.Marshal(event)
	if err != nil {
		return err
	}
	entry = append(entry, '\n')
	if f.journalBytes+int64(len(entry)) > stateLimit {
		return errors.New("journal bound reached")
	}
	n, err := f.journal.Write(entry)
	f.journalBytes += int64(n)
	if err != nil || n != len(entry) {
		return errors.New("remote journal append failed")
	}
	if file, ok := f.journal.(*os.File); ok {
		if err = file.Sync(); err != nil {
			return err
		}
	}
	f.remote.Events = append(f.remote.Events, event)
	return f.commitRemote()
}
func (s *contractSeed) validate() error {
	if s == nil {
		return nil
	}
	if s.Schema != 1 || (s.Gate != "primitive-contract" && s.Gate != "installed-traffic") || len(s.ApplicationSHA256) != 64 || strings.ToLower(s.ApplicationSHA256) != s.ApplicationSHA256 {
		return errors.New("invalid contract seed identity")
	}
	if _, err := hex.DecodeString(s.ApplicationSHA256); err != nil {
		return err
	}
	if s.Gate == "installed-traffic" {
		if len(s.Peers) != len(ownedPeerRoles) {
			return errors.New("installed shared API requires all four exact peers")
		}
		for ip, role := range ownedPeerRoles {
			phase := "passive"
			if strings.HasPrefix(role, "original-") {
				phase = "active"
			}
			if s.Peers[ip] != (peerPolicy{Role: role, Phase: phase}) {
				return errors.New("installed peer initial policy rejected")
			}
		}
	}
	for ip, policy := range s.Peers {
		if ownedPeerRoles[ip] != policy.Role || (policy.Phase != "active" && policy.Phase != "passive") {
			return errors.New("invalid exact remote peer policy")
		}
	}
	if s.Fleet != nil {
		if s.Fleet.Authorization == "" || strings.ContainsAny(s.Fleet.Authorization, "\r\n") || len(s.Fleet.Hosts) > 128 || len(s.Fleet.Commands) > 128 {
			return errors.New("invalid Fleet seed bounds")
		}
		ids := map[int]string{}
		uuids := map[string]bool{}
		for _, host := range s.Fleet.Hosts {
			if host.ID < 1 || !commandID.MatchString(host.UUID) || ids[host.ID] != "" || uuids[host.UUID] || (host.Platform != "darwin" && host.Platform != "windows") {
				return errors.New("invalid duplicate Fleet identity")
			}
			if _, err := time.Parse(time.RFC3339Nano, host.EnrolledAt); err != nil {
				return err
			}
			if host.Platform == "darwin" {
				if _, err := time.Parse(time.RFC3339Nano, host.MDMEnrolledAt); err != nil {
					return err
				}
			}
			ids[host.ID] = host.UUID
			uuids[host.UUID] = true
		}
		seen := map[string]bool{}
		for _, c := range s.Fleet.Commands {
			if !commandID.MatchString(c.UUID) || seen[c.UUID] || ids[c.HostID] != c.HostUUID || c.RequestType != "CertificateList" || c.Posts != 0 || c.Mode != "" || c.UpdatedAt != "" || c.Script != "" || c.ExecutionID != "" || c.Command != "" || c.BodySHA256 != "" {
				return errors.New("retained command seed cannot fabricate request evidence")
			}
			if _, err := time.Parse(time.RFC3339Nano, c.CreatedAt); err != nil {
				return err
			}
			seen[c.UUID] = true
		}
	}
	if s.OTLP != nil {
		intake := s.OTLP
		if intake.Host == "otlp.task11.test" {
			if intake.Authorization == "" || intake.APIKey != "" {
				return errors.New("invalid primitive intake credential")
			}
		} else {
			permitted := false
			for _, site := range []string{"datadoghq.com", "us3.datadoghq.com", "us5.datadoghq.com", "datadoghq.eu", "ap1.datadoghq.com", "ap2.datadoghq.com"} {
				permitted = permitted || intake.Host == "otlp."+site
			}
			if !permitted || intake.APIKey == "" || intake.Authorization != "" {
				return errors.New("unsupported shipping business intake authority")
			}
		}
		if strings.ContainsAny(intake.Authorization+intake.APIKey, "\r\n") {
			return errors.New("invalid intake credential")
		}
	}

	return nil
}

// Persist semantic response evidence while keeping secret bytes and bearer
// credentials out of the journal. Actual payloads stay in private API state.
func (f *fixture) observeResponse(r *http.Request, payload any) {
	f.observation = nil
	host := strings.Split(r.Host, ":")[0]
	if host == "fleet.task11.test" && r.Method == "GET" {
		f.observation, _ = json.Marshal(payload)
		return
	}
	if host == "secretmanager.googleapis.com" {
		raw, _ := json.Marshal(payload)
		var response struct {
			Name    string `json:"name"`
			State   string `json:"state"`
			Payload struct {
				Data string `json:"data"`
			} `json:"payload"`
		}
		if json.Unmarshal(raw, &response) == nil && response.Name != "" {
			out := map[string]string{"name": response.Name, "state": response.State}
			if data, err := base64.StdEncoding.DecodeString(response.Payload.Data); err == nil && len(data) > 0 {
				out["payload_sha256"] = digestBytes(data)
			}
			f.observation, _ = json.Marshal(out)
		}
	}
}

// A transport must establish this durable latch before decoding or dispatching.
// A refused/incomplete receive, crash or exhausted journal never clears it. Any
// sentinel (including empty or malformed) blocks every subsequent locked reader.
// Only the creating operation may remove its exact inode after durable recording.
const incompleteEvidenceFile = "transport-incomplete"

func (f *fixture) beginTransportEvidence() (func() error, error) {
	if f.config.Contract == nil {
		return func() error { return nil }, nil
	}
	if f.incompleteEvidence {
		return nil, errors.New("transport evidence already incomplete")
	}
	f.incompleteEvidence = true
	if f.stateRoot == "" {
		return func() error { f.incompleteEvidence = false; return nil }, nil
	}
	path := filepath.Join(f.stateRoot, incompleteEvidenceFile)
	file, err := privateFile(path, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL)
	if err != nil {
		return nil, err
	}
	info, err := file.Stat()
	if err == nil {
		_, err = file.Write([]byte("incomplete-transport-v1\n" + f.seedSHA256 + "\n"))
	}
	if err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil {
		return nil, err
	}
	if closeErr != nil {
		return nil, closeErr
	}
	parent, err := privateParent(path)
	if err != nil {
		return nil, err
	}
	err = unix.Fsync(parent)
	_ = unix.Close(parent)
	if err != nil {
		return nil, err
	}
	return func() error {
		current, err := privateFile(path, unix.O_RDONLY)
		if err != nil {
			return err
		}
		currentInfo, err := current.Stat()
		_ = current.Close()
		if err != nil || !os.SameFile(info, currentInfo) {
			return errors.New("transport sentinel ownership changed")
		}
		parent, err := privateParent(path)
		if err != nil {
			return err
		}
		defer func() { _ = unix.Close(parent) }()
		if err = unix.Unlinkat(parent, incompleteEvidenceFile, 0); err != nil {
			return err
		}
		if err = unix.Fsync(parent); err != nil {
			return err
		}
		f.incompleteEvidence = false
		return nil
	}, nil
}
