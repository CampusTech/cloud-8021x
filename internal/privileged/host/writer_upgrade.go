package host

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	"github.com/CampusTech/cloud-8021x/internal/config"
	"github.com/CampusTech/cloud-8021x/internal/domain"
)

// ValidateWriterUpgrade permits configuration evolution within one exact trust,
// database and node pair. Transfer of any of these authorities is separate work.
func ValidateWriterUpgrade(old, next config.Config) error {
	a, b := old.Bootstrap, next.Bootstrap
	if old.StateTransition != next.StateTransition || old.InstanceID != next.InstanceID || a.Project != b.Project || a.ProjectNumber != b.ProjectNumber || a.LocalAddress != b.LocalAddress || a.PeerAddress != b.PeerAddress || a.PeerDNS != b.PeerDNS || a.RuntimeRole != b.RuntimeRole || a.NativeRole != b.NativeRole || a.ECKMS != b.ECKMS || a.RSAKMS != b.RSAKMS || !reflect.DeepEqual(old.Database, next.Database) {
		return errors.New("writer upgrade changes protected authority; coordinated transfer required")
	}
	return nil
}

type writerRetirement struct {
	Transition, ReceiptSHA256 string
	Native                    map[string]string
}

// BindWriterRetirement is called after physical old fence proof and before the
// installation tree swap. Its evidence only becomes usable when this exact
// transaction is the completed installation with its matching credential cache.
func (t *Transaction) BindWriterRetirement(id string, layout []File) error {
	r, data, e := loadWriterReceipt(id)
	if e != nil {
		return e
	}
	if e = verifyWriterMasks(r); e != nil {
		if e = verifyRetiredWriter(r, layout); e != nil {
			return e
		}
	}
	t.receipt.WriterRetirement = &writerRetirement{Transition: id, ReceiptSHA256: digestBytes(data)}
	return t.persist(t.receipt.Phase)
}
func loadWriterReceipt(id string) (writerReceipt, []byte, error) {
	dir, e := writerReceiptDirectory(id)
	if e != nil {
		return writerReceipt{}, nil, e
	}
	data, e := readPrivateCache(filepath.Join(dir, "receipt.json"), 16<<20)
	if e != nil {
		return writerReceipt{}, nil, e
	}
	r, e := decodeWriterReceipt(data, id)
	if e != nil {
		return r, nil, e
	}
	done, e := readPrivateCache(filepath.Join(dir, "complete"), 128)
	if e != nil || string(done) != digestBytes(data) {
		return r, nil, errors.New("writer fence incomplete")
	}
	return r, data, nil
}
func verifyRetiredWriter(r writerReceipt, layout []File) error {
	cache, _, e := committedCredentialCache(layout)
	if e != nil {
		return e
	}
	data, e := readPrivateCache(filepath.Join(transactionRoot, cache.Reference, "receipt.json"), 64<<20)
	if e != nil {
		return e
	}
	var receipt Receipt
	if domain.DecodeJSONStrict(data, &receipt) != nil || receipt.ID != cache.Reference || receipt.Phase != "complete" || receipt.WriterRetirement == nil {
		return errors.New("completed native retirement evidence missing")
	}
	_, original, e := loadWriterReceipt(r.Transition)
	if e != nil {
		return e
	}
	retirement := receipt.WriterRetirement
	if retirement.Transition != r.Transition || retirement.ReceiptSHA256 != digestBytes(original) || len(retirement.Native) == 0 || len(retirement.Native) > 64 {
		return errors.New("native retirement receipt mismatch")
	}
	// Bind the complete replacement tree, including absence of imported Python.
	// A missing old module alone is never treated as a fence.
	remaining := map[string]string{}
	for p, h := range retirement.Native {
		if !AllowedFile(radiusDirectory+"/"+p) || cache.Bindings[radiusDirectory+"/"+p] != h {
			return errors.New("retirement differs from committed native tree")
		}
		remaining[p] = h
	}
	count := 0
	e = filepath.WalkDir(radiusDirectory, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		count++
		if count > 256 {
			return errors.New("native tree exceeds retirement bound")
		}
		if d.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(radiusDirectory, path)
		if err != nil {
			return err
		}
		want, ok := remaining[rel]
		if !ok {
			return errors.New("unbound file in retired native tree")
		}
		got, err := installedHash(path, 16<<20)
		if err != nil || got != want {
			return errors.New("retired native tree changed")
		}
		delete(remaining, rel)
		return nil
	})
	if e != nil {
		return e
	}
	if len(remaining) != 0 {
		return errors.New("native retirement file missing")
	}
	return verifyWriterNonNativeMasks(r)
}

// RevalidateLegacyWriterFence is a read-only physical check. No saved original,
// receipt or inode is replaced; a completed Go tree needs exact retirement proof.
func RevalidateLegacyWriterFence(ctx context.Context, id, node string, layout []File) (string, error) {
	return revalidateLegacyWriterFence(ctx, id, node, layout, execute)
}
func revalidateLegacyWriterFence(ctx context.Context, id, node string, layout []File, run commandRunner) (string, error) {
	if os.Geteuid() != 0 {
		return "", errors.New("root writer verification required")
	}
	r, data, e := loadWriterReceipt(id)
	if e != nil {
		return "", e
	}
	if r.Node != node {
		return "", errors.New("writer node mismatch")
	}
	if e = verifyWriterMasks(r); e != nil {
		if e = verifyRetiredWriter(r, layout); e != nil {
			return "", e
		}
	}
	if e = writerUnitsQuiescent(ctx, run, legacyWriterUnits); e != nil {
		return "", e
	}
	unlock, e := lockLegacyWriters()
	if e != nil {
		return "", e
	}
	defer unlock()
	if e = checkObservedWriterProcesses(r.Processes); e != nil {
		return "", e
	}
	return digestBytes(data), nil
}

// AppendWriterBinding keeps immutable local upgrade observations. The caller has
// checked completed credentials/active config and same authority under root gate.
func AppendWriterBinding(id, node, prior, next, receipt string) error {
	dir, e := writerReceiptDirectory(id)
	if e != nil {
		return e
	}
	for _, h := range []string{prior, next, receipt} {
		if len(h) != 64 || strings.Trim(h, "0123456789abcdef") != "" {
			return errors.New("invalid upgrade digest")
		}
	}
	r, data, e := loadWriterReceipt(id)
	if e != nil {
		return e
	}
	if r.Node != node || digestBytes(data) != receipt {
		return errors.New("upgrade original receipt mismatch")
	}
	binding, e := json.Marshal(struct{ Node, Prior, Next, Receipt string }{node, prior, next, receipt})
	if e != nil {
		return e
	}
	path := filepath.Join(dir, "binding-"+next+".json")
	if existing, e := readPrivateCache(path, 4096); e == nil {
		if string(existing) != string(binding) {
			return errors.New("upgrade binding differs")
		}
		return nil
	} else if !errors.Is(e, os.ErrNotExist) {
		return e
	}
	if e = privateWrite(path, binding, 0600); e != nil {
		return e
	}
	return syncWriterDirectory(dir)
}
