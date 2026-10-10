package migration

import "testing"

func TestCertificateStateRejectsOrphanCommand(t *testing.T) {
	raw := []byte(`{"version":1,"source":"https://fleet.example.invalid","trust":null,"hosts":{},"commands":[{"uuid":"x","created_at":1,"hosts":{"missing":[1,1,null]}}]}`)
	if _, err := DecodeCertificates(raw); err == nil {
		t.Fatal("orphan command passed validation")
	}
}
