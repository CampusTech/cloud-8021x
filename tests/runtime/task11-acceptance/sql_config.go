package main

import (
	"errors"

	"github.com/CampusTech/cloud-8021x/internal/adoption"
	"github.com/CampusTech/cloud-8021x/internal/config"
	"github.com/CampusTech/cloud-8021x/internal/privileged/host"
)

// The production callback is host.Snapshot: checked no-follow ancestry and a
// retained file descriptor enforce regular type, root ownership and one link.
// Installed configuration uses the exact shipping0644 mode; private incoming
// inputs continue to use the separate0600-only reader.
func observeSQLConfig(pin string, snapshot func(host.File) (host.SavedFile, error)) error {
	if !validSHA(pin) {
		return errors.New("installed and enrolled configuration differ")
	}
	saved, err := snapshot(host.File{Path: "/etc/cloud-8021x/config.yaml", UID: 0})
	defer clear(saved.Data)
	if err != nil || !saved.Exists || saved.Path != "/etc/cloud-8021x/config.yaml" || saved.UID != 0 || saved.Mode != 0644 || len(saved.Data) > config.MaxConfigBytes || adoption.Digest(saved.Data) != pin {
		return errors.New("installed and enrolled configuration differ")
	}
	return nil
}
