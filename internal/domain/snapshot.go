package domain

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"unicode/utf8"
)

const MaxSnapshotBytes = 16 << 20

// Pointer values deliberately retain legacy null ambiguity entries.
type DeviceRecord struct {
	DeviceID   DeviceID   `json:"device_id"`
	Groups     []GroupID  `json:"groups"`
	Enrolled   bool       `json:"enrolled"`
	ObservedAt *Timestamp `json:"observed_at,omitempty"`
}
type Snapshot struct {
	Version         int                          `json:"version"`
	UpdatedAt       Timestamp                    `json:"updated_at"`
	Identities      map[string]*DeviceRecord     `json:"identities"`
	Certificates    map[string]*DeviceRecord     `json:"certificates,omitempty"`
	HardwareSerials map[string]*DeviceRecord     `json:"hardware_serials,omitempty"`
	Devices         map[DeviceID]*DeviceMetadata `json:"devices,omitempty"`
}

// MarshalJSON keeps empty v2 maps present, while omitting them entirely in v1.
func (s Snapshot) MarshalJSON() ([]byte, error) {
	type legacy struct {
		Version    int                          `json:"version"`
		UpdatedAt  Timestamp                    `json:"updated_at"`
		Identities map[string]*DeviceRecord     `json:"identities"`
		Devices    map[DeviceID]*DeviceMetadata `json:"devices,omitempty"`
	}
	if s.Version == 1 {
		return json.Marshal(legacy{s.Version, s.UpdatedAt, s.Identities, s.Devices})
	}
	type current struct {
		Version         int                          `json:"version"`
		UpdatedAt       Timestamp                    `json:"updated_at"`
		Identities      map[string]*DeviceRecord     `json:"identities"`
		Certificates    map[string]*DeviceRecord     `json:"certificates"`
		HardwareSerials map[string]*DeviceRecord     `json:"hardware_serials"`
		Devices         map[DeviceID]*DeviceMetadata `json:"devices,omitempty"`
	}
	return json.Marshal(current(s))
}
func NormalizeIdentity(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimSpace(strings.TrimSuffix(s, " Campus WiFi"))
	candidate := strings.TrimPrefix(s, "urn:uuid:")
	candidate = strings.Trim(candidate, "{}")
	compact := strings.ReplaceAll(candidate, "-", "")
	if len(compact) == 32 {
		if _, err := hex.DecodeString(compact); err == nil {
			compact = strings.ToLower(compact)
			return compact[:8] + "-" + compact[8:12] + "-" + compact[12:16] + "-" + compact[16:20] + "-" + compact[20:]
		}
	}
	return s
}
func NormalizeFingerprint(s string) (string, error) {
	if len(s) != 64 {
		return "", errors.New("invalid certificate SHA256 fingerprint")
	}
	if _, err := hex.DecodeString(s); err != nil {
		return "", errors.New("invalid certificate SHA256 fingerprint")
	}
	return strings.ToLower(s), nil
}
func metadataValid(m *DeviceMetadata) bool {
	if m == nil {
		return false
	}
	for _, s := range []string{m.Serial, m.Name, m.Model, m.Owner} {
		if !utf8.ValidString(s) || utf8.RuneCountInString(s) > 1024 {
			return false
		}
	}
	return true
}
func BuildSnapshot(devices []Device, now Timestamp) (Snapshot, error) {
	s := Snapshot{Version: 1, UpdatedAt: now, Identities: map[string]*DeviceRecord{}, Certificates: map[string]*DeviceRecord{}, HardwareSerials: map[string]*DeviceRecord{}, Devices: map[DeviceID]*DeviceMetadata{}}
	add := func(m map[string]*DeviceRecord, key string, r *DeviceRecord) {
		old, exists := m[key]
		if exists && !reflect.DeepEqual(old, r) {
			m[key] = nil
		} else if !exists {
			m[key] = r
		}
	}
	for _, d := range devices {
		if d.ID == "" || d.Groups == nil {
			return Snapshot{}, errors.New("inventory device requires stable ID and groups")
		}
		r := &DeviceRecord{DeviceID: d.ID, Groups: append([]GroupID{}, d.Groups...), Enrolled: d.Enrolled}
		if d.HardwareSerial != "" {
			add(s.HardwareSerials, d.HardwareSerial, r)
		}
		for _, alias := range d.Identities {
			alias = NormalizeIdentity(alias)
			if alias != "" {
				add(s.Identities, alias, r)
			}
		}
		if d.Metadata != nil || d.MetadataPresent {
			var m *DeviceMetadata
			if metadataValid(d.Metadata) {
				copy := *d.Metadata
				m = &copy
			}
			old, exists := s.Devices[d.ID]
			if exists && !reflect.DeepEqual(old, m) {
				s.Devices[d.ID] = nil
			} else if !exists {
				s.Devices[d.ID] = m
			}
		}
		if d.Fingerprints != nil {
			s.Version = 2
			for _, fp := range *d.Fingerprints {
				fp, err := NormalizeFingerprint(fp)
				if err != nil {
					return Snapshot{}, err
				}
				observed := d.CertificatesObservedAt
				cr := &DeviceRecord{DeviceID: r.DeviceID, Groups: append([]GroupID{}, r.Groups...), Enrolled: r.Enrolled, ObservedAt: &observed}
				add(s.Certificates, fp, cr)
			}
		}
	}
	if s.Version == 1 {
		s.Certificates = nil
		s.HardwareSerials = nil
	}
	if len(s.Devices) == 0 {
		s.Devices = nil
	}
	return s, nil
}
func (s Snapshot) Clone() Snapshot {
	clone := s
	copyMap := func(in map[string]*DeviceRecord) map[string]*DeviceRecord {
		if in == nil {
			return nil
		}
		out := make(map[string]*DeviceRecord, len(in))
		for k, v := range in {
			if v == nil {
				out[k] = nil
				continue
			}
			r := *v
			if v.Groups != nil {
				r.Groups = append([]GroupID{}, v.Groups...)
			}
			if v.ObservedAt != nil {
				at := *v.ObservedAt
				r.ObservedAt = &at
			}
			out[k] = &r
		}
		return out
	}
	clone.Identities = copyMap(s.Identities)
	clone.Certificates = copyMap(s.Certificates)
	clone.HardwareSerials = copyMap(s.HardwareSerials)
	if s.Devices != nil {
		clone.Devices = map[DeviceID]*DeviceMetadata{}
		for k, v := range s.Devices {
			if v == nil {
				clone.Devices[k] = nil
			} else {
				m := *v
				clone.Devices[k] = &m
			}
		}
	}
	return clone
}

// DecodeSnapshot accepts deployed v1/v2 schemas and conservatively discards malformed display metadata.
func DecodeSnapshot(r io.Reader) (Snapshot, error) {
	data, err := io.ReadAll(io.LimitReader(r, MaxSnapshotBytes+1))
	if err != nil || len(data) > MaxSnapshotBytes {
		return Snapshot{}, errors.New("inventory read failed or exceeds limit")
	}
	var wire struct {
		Version         int                          `json:"version"`
		UpdatedAt       *Timestamp                   `json:"updated_at"`
		Identities      map[string]*DeviceRecord     `json:"identities"`
		Certificates    map[string]*DeviceRecord     `json:"certificates"`
		HardwareSerials map[string]*DeviceRecord     `json:"hardware_serials"`
		Devices         map[DeviceID]json.RawMessage `json:"devices"`
	}
	if err := DecodeJSONStrict(data, &wire); err != nil {
		return Snapshot{}, err
	}
	if wire.UpdatedAt == nil {
		return Snapshot{}, errors.New("missing inventory observation timestamp")
	}
	s := Snapshot{Version: wire.Version, UpdatedAt: *wire.UpdatedAt, Identities: wire.Identities, Certificates: wire.Certificates, HardwareSerials: wire.HardwareSerials}
	if (s.Version != 1 && s.Version != 2) || s.Identities == nil || (s.Version == 2 && (s.Certificates == nil || s.HardwareSerials == nil)) {
		return Snapshot{}, errors.New("unsupported or incomplete inventory snapshot")
	}
	for _, m := range []map[string]*DeviceRecord{s.Identities, s.Certificates, s.HardwareSerials} {
		for _, d := range m {
			if d != nil && (d.DeviceID == "" || d.Groups == nil) {
				return Snapshot{}, errors.New("invalid device record")
			}
		}
	}
	for fp := range s.Certificates {
		if normalized, err := NormalizeFingerprint(fp); err != nil || normalized != fp {
			return Snapshot{}, errors.New("invalid inventory fingerprint")
		}
	}
	if wire.Devices != nil {
		s.Devices = map[DeviceID]*DeviceMetadata{}
		for id, raw := range wire.Devices {
			var fields map[string]json.RawMessage
			var m DeviceMetadata
			if json.Unmarshal(raw, &fields) != nil || len(fields) != 4 || DecodeJSONStrict(raw, &m) != nil || !metadataValid(&m) {
				s.Devices[id] = nil
			} else {
				s.Devices[id] = &m
			}
		}
	}
	return s, nil
}

// DecodeJSONStrict rejects duplicate keys at every depth as well as unknown fields and trailing documents.
func DecodeJSONStrict(data []byte, v any) error {
	tokens := json.NewDecoder(bytes.NewReader(data))
	var walk func() error
	walk = func() error {
		tok, err := tokens.Token()
		if err != nil {
			return err
		}
		delim, ok := tok.(json.Delim)
		if !ok {
			return nil
		}
		switch delim {
		case '{':
			seen := map[string]bool{}
			for tokens.More() {
				key, err := tokens.Token()
				if err != nil {
					return err
				}
				k, ok := key.(string)
				if !ok || seen[k] {
					return errors.New("duplicate or invalid JSON key")
				}
				seen[k] = true
				if err := walk(); err != nil {
					return err
				}
			}
			_, err = tokens.Token()
			return err
		case '[':
			for tokens.More() {
				if err := walk(); err != nil {
					return err
				}
			}
			_, err = tokens.Token()
			return err
		default:
			return errors.New("invalid JSON")
		}
	}
	if err := walk(); err != nil {
		return errors.New("invalid or duplicate JSON")
	}
	if _, err := tokens.Token(); !errors.Is(err, io.EOF) {
		return errors.New("trailing JSON")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return errors.New("invalid JSON schema")
	}
	return nil
}

type SnapshotStore struct{ value atomic.Pointer[Snapshot] }

func (s *SnapshotStore) Publish(batch DeviceSnapshot) error {
	if !batch.Complete {
		return ErrIncompleteSnapshot
	}
	next, err := BuildSnapshot(batch.Devices, batch.ObservedAt)
	if err != nil {
		return err
	}
	return s.Set(next)
}
func (s *SnapshotStore) Set(snapshot Snapshot) error {
	data, err := json.Marshal(snapshot)
	if err != nil {
		return errors.New("invalid inventory snapshot")
	}
	if _, err := DecodeSnapshot(bytes.NewReader(data)); err != nil {
		return err
	}
	copy := snapshot.Clone()
	s.value.Store(&copy)
	return nil
}

func (s *SnapshotStore) Load() Snapshot {
	snapshot := s.value.Load()
	if snapshot == nil {
		return Snapshot{}
	}
	return snapshot.Clone()
}
func PublishSnapshotFile(path string, s Snapshot) error {
	data, err := json.Marshal(s)
	if err != nil {
		return err
	}
	if _, err := DecodeSnapshot(bytes.NewReader(data)); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".inventory-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(f.Name()) }()
	if _, err = f.Write(data); err == nil {
		err = f.Chmod(0644)
	}
	if err == nil {
		err = f.Sync()
	}
	err = errors.Join(err, f.Close())
	if err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}

// InventoryView exposes only bounded copies of individual records. Authorization
// keeps one immutable generation without cloning the full inventory per request.
type InventoryView interface {
	SchemaVersion() int
	Updated() Timestamp
	ByIdentity(string) *DeviceRecord
	ByCertificate(string) *DeviceRecord
	BySerial(string) *DeviceRecord
	MetadataFor(DeviceID) *DeviceMetadata
}

func copyRecord(in *DeviceRecord) *DeviceRecord {
	if in == nil {
		return nil
	}
	out := *in
	if in.Groups != nil {
		out.Groups = append([]GroupID{}, in.Groups...)
	}
	if in.ObservedAt != nil {
		at := *in.ObservedAt
		out.ObservedAt = &at
	}
	return &out
}
func (s Snapshot) SchemaVersion() int                    { return s.Version }
func (s Snapshot) Updated() Timestamp                    { return s.UpdatedAt }
func (s Snapshot) ByIdentity(name string) *DeviceRecord  { return copyRecord(s.Identities[name]) }
func (s Snapshot) ByCertificate(fp string) *DeviceRecord { return copyRecord(s.Certificates[fp]) }
func (s Snapshot) BySerial(serial string) *DeviceRecord  { return copyRecord(s.HardwareSerials[serial]) }
func (s Snapshot) MetadataFor(id DeviceID) *DeviceMetadata {
	m := s.Devices[id]
	if m == nil {
		return nil
	}
	out := *m
	return &out
}

type snapshotView struct{ snapshot *Snapshot }

func (v snapshotView) SchemaVersion() int {
	if v.snapshot == nil {
		return 0
	}
	return v.snapshot.SchemaVersion()
}
func (v snapshotView) Updated() Timestamp {
	if v.snapshot == nil {
		return 0
	}
	return v.snapshot.Updated()
}
func (v snapshotView) ByIdentity(name string) *DeviceRecord {
	if v.snapshot == nil {
		return nil
	}
	return v.snapshot.ByIdentity(name)
}
func (v snapshotView) ByCertificate(fp string) *DeviceRecord {
	if v.snapshot == nil {
		return nil
	}
	return v.snapshot.ByCertificate(fp)
}
func (v snapshotView) BySerial(serial string) *DeviceRecord {
	if v.snapshot == nil {
		return nil
	}
	return v.snapshot.BySerial(serial)
}
func (v snapshotView) MetadataFor(id DeviceID) *DeviceMetadata {
	if v.snapshot == nil {
		return nil
	}
	return v.snapshot.MetadataFor(id)
}
func (s *SnapshotStore) View() InventoryView { return snapshotView{snapshot: s.value.Load()} }
