package host

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/CampusTech/cloud-8021x/internal/domain"
	"golang.org/x/sys/unix"
)

type nativeTreeEntry struct {
	Path, Kind, SHA256, Link string
	UID, GID                 uint32
	Mode                     uint32
	Size                     int64
	Links                    uint64
	ModifiedNS               int64
}
type rollbackLineage struct {
	Transaction, Transition, WriterSHA256, ManifestSHA256 string
	Directories                                           []writerDirectory
}

// The manifest describes the complete copy, without inode numbers which cp
// necessarily replaces. Root-only transaction storage makes it immutable.
func nativeTreeManifest(root string) ([]byte, error) {
	entries := []nativeTreeEntry{}
	var total int64
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if len(entries) >= 8192 {
			return errors.New("native manifest exceeds entry bound")
		}
		var st unix.Stat_t
		if err = unix.Lstat(path, &st); err != nil {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		entry := nativeTreeEntry{Path: rel, UID: st.Uid, GID: st.Gid, Mode: uint32(st.Mode) & 07777}
		entry.ModifiedNS = info.ModTime().UnixNano()
		switch st.Mode & unix.S_IFMT {
		case unix.S_IFDIR:
			entry.Kind = "directory"
		case unix.S_IFLNK:
			entry.Kind = "link"
			entry.Link, err = os.Readlink(path)
			target := filepath.Clean(filepath.Join(filepath.Dir(path), entry.Link))
			if err != nil || filepath.IsAbs(entry.Link) || !strings.HasPrefix(target, root+"/") {
				return errors.New("native manifest link escapes tree")
			}
		case unix.S_IFREG:
			if st.Size < 0 || st.Size > 16<<20 || st.Nlink != 1 {
				return errors.New("native manifest file outside bound")
			}
			total += st.Size
			if total > 64<<20 {
				return errors.New("native manifest exceeds byte bound")
			}
			fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
			if err != nil {
				return err
			}
			file := os.NewFile(uintptr(fd), path)
			data, readErr := io.ReadAll(io.LimitReader(file, (16<<20)+1))
			var after unix.Stat_t
			statErr := unix.Fstat(fd, &after)
			afterInfo, infoErr := file.Stat()
			closeErr := file.Close()
			if readErr != nil || statErr != nil || closeErr != nil || infoErr != nil || !afterInfo.ModTime().Equal(info.ModTime()) || (st.Dev != after.Dev || st.Ino != after.Ino || st.Mode != after.Mode || st.Nlink != after.Nlink || st.Uid != after.Uid || st.Gid != after.Gid || st.Size != after.Size) || int64(len(data)) != st.Size {
				return errors.New("native manifest file changed")
			}
			entry.Kind = "file"
			entry.Size = st.Size
			entry.Links = uint64(st.Nlink)
			entry.SHA256 = digestBytes(data)
		default:
			return errors.New("unsupported native manifest object")
		}
		entries = append(entries, entry)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return json.Marshal(entries)
}
func (t *Transaction) originalNativeManifest() ([]byte, error) {
	data, e := readPrivateCache(filepath.Join(t.directory, "radius-manifest.json"), 4<<20)
	if e != nil || t.receipt.RadiusManifestSHA256 == "" || digestBytes(data) != t.receipt.RadiusManifestSHA256 {
		return nil, errors.New("original native manifest unavailable")
	}
	return data, nil
}
func (t *Transaction) recordRollbackLineage() error {
	if t.receipt.WriterRetirement == nil || !t.receipt.HadRadius {
		return nil
	}
	r, raw, e := loadWriterReceipt(t.receipt.WriterRetirement.Transition)
	if e != nil {
		return e
	}
	if digestBytes(raw) != t.receipt.WriterRetirement.ReceiptSHA256 {
		return errors.New("rollback writer receipt differs")
	}
	// Completed Go installations have retired this lineage entirely. Their
	// existing completed installation/cache binding remains the authority.
	if _, e = os.Lstat(legacyVLANModule); errors.Is(e, os.ErrNotExist) {
		return nil
	} else if e != nil {
		return e
	}
	if e = proveNativeProcessesGone(r.NativeUID); e != nil {
		return e
	}
	if e = checkObservedWriterProcesses(r.Processes); e != nil {
		return e
	}
	unlock, e := lockLegacyWriters()
	if e != nil {
		return e
	}
	defer unlock()
	original, e := t.originalNativeManifest()
	if e != nil {
		return e
	}
	current, e := nativeTreeManifest(radiusDirectory)
	if e != nil || !bytes.Equal(current, original) {
		return errors.New("restored native tree differs from original manifest")
	}
	directories, _, e := snapshotWriterLineage()
	if e != nil {
		return e
	}
	candidate := r
	candidate.Directories = directories
	if e = verifyWriterLineageExact(candidate); e != nil {
		return e
	}
	observation := rollbackLineage{t.receipt.ID, r.Transition, digestBytes(raw), digestBytes(original), directories}
	data, e := json.Marshal(observation)
	if e != nil {
		return e
	}
	dir, e := writerReceiptDirectory(r.Transition)
	if e != nil {
		return e
	}
	path := filepath.Join(dir, "rollback-"+t.receipt.ID+".json")
	if old, e := readPrivateCache(path, 16<<10); e == nil {
		if !bytes.Equal(old, data) {
			return errors.New("rollback lineage observation changed")
		}
		return nil
	} else if !errors.Is(e, os.ErrNotExist) {
		return e
	}
	if e = privateWrite(path, data, 0600); e != nil {
		return e
	}
	return syncWriterDirectory(dir)
}
func verifyRollbackLineage(r writerReceipt) error {
	dir, e := writerReceiptDirectory(r.Transition)
	if e != nil {
		return e
	}
	_, original, e := loadWriterReceipt(r.Transition)
	if e != nil {
		return e
	}
	directory, e := os.Open(dir)
	if e != nil {
		return e
	}
	names, e := directory.Readdirnames(4097)
	_ = directory.Close()
	if (e != nil && !errors.Is(e, io.EOF)) || len(names) > 4096 {
		return errors.New("rollback observations exceed bound")
	}
	for _, name := range names {
		if !regexp.MustCompile(`^rollback-[0-9a-f]{32}\.json$`).MatchString(name) {
			continue
		}
		data, e := readPrivateCache(filepath.Join(dir, name), 16<<10)
		if e != nil {
			return e
		}
		var observation rollbackLineage
		if domain.DecodeJSONStrict(data, &observation) != nil || name != "rollback-"+observation.Transaction+".json" || observation.Transition != r.Transition || observation.WriterSHA256 != digestBytes(original) || len(observation.Directories) != len(r.Directories) {
			return errors.New("invalid rollback lineage observation")
		}
		candidate := r
		candidate.Directories = observation.Directories
		for i, d := range observation.Directories {
			old := r.Directories[i]
			if d.Path != old.Path || d.UID != 0 || d.GID != old.GID || d.Mode != writerDirectoryMode(old, r.NativeUID) {
				return errors.New("rollback lineage metadata changed")
			}
		}
		if verifyWriterLineageExact(candidate) != nil {
			continue
		}
		transactionDir := filepath.Join(transactionRoot, observation.Transaction)
		receiptData, e := readPrivateCache(filepath.Join(transactionDir, "receipt.json"), 64<<20)
		if e != nil {
			return e
		}
		var receipt Receipt
		if domain.DecodeJSONStrict(receiptData, &receipt) != nil || receipt.ID != observation.Transaction || receipt.Phase != "rolled-back" || receipt.WriterRetirement == nil || receipt.WriterRetirement.Transition != r.Transition || receipt.WriterRetirement.ReceiptSHA256 != observation.WriterSHA256 || receipt.RadiusManifestSHA256 != observation.ManifestSHA256 {
			return errors.New("rollback not exactly completed")
		}
		manifest, e := readPrivateCache(filepath.Join(transactionDir, "radius-manifest.json"), 4<<20)
		if e != nil || digestBytes(manifest) != observation.ManifestSHA256 {
			return errors.New("rollback original manifest changed")
		}
		current, e := nativeTreeManifest(radiusDirectory)
		if e != nil || !bytes.Equal(current, manifest) {
			return errors.New("rollback tree changed")
		}
		return nil
	}
	return errors.New("protected writer lineage has no completed rollback binding")
}
