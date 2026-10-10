package host

import (
	"bytes"
	"testing"
)

func TestAdoptionSnapshotPreservesOriginalAgeAndStickyNulls(t *testing.T) {
	original := []byte(`{"version":2,"updated_at":1234.25,"identities":{"ambiguous":null},"certificates":{},"hardware_serials":{}}`)
	got, err := validateAdoptionSnapshot(original, "fingerprint", true)
	if err != nil || !bytes.Equal(got, original) {
		t.Fatalf("adoption altered original snapshot: %q %v", got, err)
	}
	if _, err = validateAdoptionSnapshot(original, "legacy-serial", true); err == nil {
		t.Fatal("guard downgraded")
	}
	if _, err = validateAdoptionSnapshot([]byte(`{"version":1,"updated_at":1234,"identities":{}}`), "fingerprint", false); err == nil {
		t.Fatal("fingerprint adoption used serial-only snapshot")
	}
	if _, err = validateAdoptionSnapshot([]byte(`{"version":2,"updated_at":1234,"identities":{},"certificates":{}}`), "fingerprint", true); err == nil {
		t.Fatal("partial policy accepted")
	}
}
