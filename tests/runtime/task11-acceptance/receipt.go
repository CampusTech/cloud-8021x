package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/adoption"
	"github.com/CampusTech/cloud-8021x/internal/config"
)

// Verify at both transfer boundaries. This controller never signs product
// envelopes or reads their private receipt keys.
func verifyReceipt(kind, role string, raw []byte, c config.Config, release string, now time.Time) error {
	if _, _, err := receiptPaths(kind, role); err != nil {
		return err
	}
	if err := c.ValidateHandoffPins(); err != nil {
		return err
	}
	b, err := adoption.ExpectedBinding(c, release)
	if err != nil {
		return err
	}
	pin := c.Deployment.SourcePrimaryKey
	if role == "radius-secondary" {
		pin = c.Deployment.SourceSecondaryKey
	}
	if kind == "parallel" {
		if role != c.InstanceID {
			return errors.New("authorization receipt belongs to another physical role")
		}
		pub, e := hex.DecodeString(pin)
		if e != nil {
			return e
		}
		_, err = adoption.Verify(raw, ed25519.PublicKey(pub), b, now)
		return err
	}
	pin = c.Deployment.DestinationPrimaryKey
	if role == "radius-secondary" {
		pin = c.Deployment.DestinationSecondaryKey
	}
	pub, err := hex.DecodeString(pin)
	if err != nil {
		return err
	}
	_, err = adoption.VerifyRollback(raw, ed25519.PublicKey(pub), b.ManifestSHA256, release, c.StateTransition, c.Deployment.ID, c.Deployment.SourceID, role, now)
	return err
}
