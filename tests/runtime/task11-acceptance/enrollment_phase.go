package main

import (
	"encoding/json"
	"errors"
	"os"
)

const passivePhasePinsPath = control + "/passive-manifests.json"
const passivePhasePinsLimit = 16 << 10

type passivePhasePins struct {
	Schema    int               `json:"schema"`
	Manifests map[string]string `json:"manifests"`
}

func validatePassivePhasePins(manifests map[string]string) error {
	if manifests == nil || len(manifests) > 4 {
		return errors.New("bounded phase manifest map required")
	}
	for phase, pin := range manifests {
		switch phase {
		case "green-primary-prepared", "green-secondary-prepared", "green-primary-deactivated", "green-secondary-deactivated":
		default:
			return errors.New("unknown passive phase manifest")
		}
		if !validSHA(pin) {
			return errors.New("canonical passive phase manifest pin required")
		}
	}
	return nil
}

// Phase evidence is separate from the independently pinned physical enrollment.
// The existing guarded writer publishes only this fixed root0600 sidecar.
func persistPassivePhasePins(e enrollment, write func(string, []byte, int) error) error {
	if err := validatePassivePhasePins(e.Passive.Manifests); err != nil {
		return err
	}
	raw, err := json.Marshal(passivePhasePins{Schema: 1, Manifests: e.Passive.Manifests})
	if err != nil || len(raw) > passivePhasePinsLimit {
		return errors.New("bounded phase evidence required")
	}
	return write(passivePhasePinsPath, raw, 0)
}

func loadPassivePhasePins(e *enrollment, read func(string, int64, int) ([]byte, error)) error {
	if len(e.Passive.Manifests) != 0 {
		return errors.New("physical enrollment already contains phase evidence")
	}
	raw, err := read(passivePhasePinsPath, passivePhasePinsLimit, 0)
	defer clear(raw)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var fields map[string]json.RawMessage
	var pins passivePhasePins
	if len(raw) > passivePhasePinsLimit || decodeExactJSON(raw, &fields) != nil || len(fields) != 2 || fields["schema"] == nil || fields["manifests"] == nil || decodeExactJSON(raw, &pins) != nil || pins.Schema != 1 {
		return errors.New("strict phase evidence object required")
	}
	if err := validatePassivePhasePins(pins.Manifests); err != nil {
		return err
	}
	// The immutable enrollment file remains byte-for-byte untouched. Only this
	// loaded value receives the independently validated phase evidence overlay.
	e.Passive.Manifests = pins.Manifests
	return nil
}
