package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
)

func phaseEnrollmentFixture() enrollment {
	pin := strings.Repeat("a", 64)
	return enrollment{Schema: 1, ApplicationSHA256: pin, ControllerSHA256: pin, Cloud: cloudPins{pin, pin, pin, pin, pin}, Passive: passivePins{ObserverSHA256: pin, ObserverSourceSHA256: pin, CloudSourceSHA256: pin, ApplicationSourceSHA: strings.Repeat("a", 40), OriginalSeedSHA256: pin}, Nodes: map[string]nodeEnrollment{"blue-primary": {strings.Repeat("a", 32), "task11-blue-primary", pin, pin}}}
}

func TestPassivePhasePersistencePreservesPhysicalEnrollmentBytes(t *testing.T) {
	e := phaseEnrollmentFixture()
	physical, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{control + "/enrollment.json": append([]byte(nil), physical...)}
	write := func(path string, raw []byte, uid int) error {
		if uid != 0 {
			t.Fatal("phase record owner changed")
		}
		files[path] = append([]byte(nil), raw...)
		return nil
	}
	pin := strings.Repeat("b", 64)
	e.Passive.Manifests = map[string]string{}
	for _, phase := range []string{"green-primary-prepared", "green-secondary-prepared", "green-primary-deactivated", "green-secondary-deactivated"} {
		e.Passive.Manifests[phase] = pin
		if err := persistPassivePhasePins(e, write); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(files[control+"/enrollment.json"], physical) {
			t.Fatal("phase evidence rewrote independently pinned physical enrollment; one CA attempt cannot cross migration phases")
		}
	}
	var stored struct {
		Schema    int               `json:"schema"`
		Manifests map[string]string `json:"manifests"`
	}
	if err := decodeExactJSON(files[control+"/passive-manifests.json"], &stored); err != nil || stored.Schema != 1 || len(stored.Manifests) != 4 {
		t.Fatal("complete separate phase evidence was not persisted", err)
	}
}

func TestPassivePhaseLoaderReadsOnlyTheFixedValidatedSidecar(t *testing.T) {
	e := phaseEnrollmentFixture()
	raw := []byte(`{"schema":1,"manifests":{"green-primary-prepared":"` + strings.Repeat("b", 64) + `"}}`)
	calls := 0
	err := loadPassivePhasePins(&e, func(path string, limit int64, uid int) ([]byte, error) {
		calls++
		if path != control+"/passive-manifests.json" || uid != 0 || limit != 16<<10 {
			t.Fatal("phase evidence reader accepted a different path, owner or bound")
		}
		return raw, nil
	})
	if err != nil || calls != 1 || e.Passive.Manifests["green-primary-prepared"] != strings.Repeat("b", 64) {
		t.Fatal("actual phase evidence not loaded alongside unchanged physical enrollment", err)
	}
}

func TestPassivePhaseLoaderAndWriterRefuseInvalidOrMixedState(t *testing.T) {
	valid := `{"schema":1,"manifests":{"green-primary-prepared":"` + strings.Repeat("b", 64) + `"}}`
	for _, raw := range []string{
		`{"schema":2,"manifests":{}}`, `{"schema":1,"manifests":null}`,
		`{"schema":1,"manifests":{"blue-primary-prepared":"` + strings.Repeat("b", 64) + `"}}`,
		strings.Replace(valid, "schema", "Schema", 1), strings.Replace(valid, "manifests", "Manifests", 1),
		strings.Replace(valid, `"schema":1`, `"schema":1,"schema":1`, 1),
		strings.Replace(valid, strings.Repeat("b", 64), strings.Repeat("B", 64), 1),
		valid + ` {}`, strings.Repeat(" ", (16<<10)+1),
	} {
		e := phaseEnrollmentFixture()
		if err := loadPassivePhasePins(&e, func(string, int64, int) ([]byte, error) { return []byte(raw), nil }); err == nil {
			t.Fatal("invalid or ambiguous phase evidence accepted")
		}
	}
	e := phaseEnrollmentFixture()
	if err := loadPassivePhasePins(&e, func(string, int64, int) ([]byte, error) { return nil, os.ErrNotExist }); err != nil {
		t.Fatal("honest pre-phase sidecar absence refused", err)
	}
	if err := loadPassivePhasePins(&e, func(string, int64, int) ([]byte, error) { return nil, os.ErrPermission }); err == nil {
		t.Fatal("unsafe sidecar failure became absence")
	}
	e.Passive.Manifests = map[string]string{"green-primary-prepared": strings.Repeat("b", 64)}
	if err := loadPassivePhasePins(&e, func(string, int64, int) ([]byte, error) { return []byte(valid), nil }); err == nil {
		t.Fatal("phase pins already mixed into physical enrollment accepted")
	}
	e.Passive.Manifests = map[string]string{"unknown-phase": strings.Repeat("b", 64)}
	written := false
	if err := persistPassivePhasePins(e, func(string, []byte, int) error { written = true; return nil }); err == nil || written {
		t.Fatal("unvalidated phase map published")
	}
	e.Passive.Manifests = map[string]string{"green-primary-prepared": strings.Repeat("b", 64)}
	failure := errors.New("private writer failure")
	if err := persistPassivePhasePins(e, func(string, []byte, int) error { return failure }); !errors.Is(err, failure) {
		t.Fatal("phase persistence error swallowed", err)
	}
}
