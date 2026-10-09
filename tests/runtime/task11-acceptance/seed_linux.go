//go:build linux

package main

import (
	"errors"
	"os"
	"path/filepath"
	"sort"

	"github.com/CampusTech/cloud-8021x/internal/adoption"
	"github.com/CampusTech/cloud-8021x/internal/domain"
)

func seedGuest() error {
	if err := fixtureGuard(); err != nil {
		return err
	}
	raw, err := readPrivate(control+"/seed-spec.json", 64<<10, 0)
	if err != nil {
		return err
	}
	var spec seedSpec
	if domain.DecodeJSONStrict(raw, &spec) != nil {
		return errors.New("strict synthetic source specification required")
	}
	files, err := generateSeed(spec)
	if err != nil {
		return err
	}
	original, err := originalManifestBytes(files)
	if err != nil {
		return err
	}
	files["original-manifest.json"] = original
	root := control + "/original-seed"
	// Exclusive directory: reruns cannot renew/reseed preserved original identity.
	if err = os.Mkdir(root, 0700); err != nil {
		return err
	}
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		path := filepath.Join(root, name)
		if err = os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			return err
		}
		if err = atomicPrivate(path, files[name], 0); err != nil {
			return err
		}
		if err = recordEvidence(evidence{Stage: "synthetic-original-seed", Node: "shared-original-input", Operation: name, Status: "generated-only-not-installed", SHA256: adoption.Digest(files[name]), Bytes: len(files[name])}); err != nil {
			return err
		}
	}
	return nil
}
