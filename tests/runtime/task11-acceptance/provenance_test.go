package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/domain"
)

func TestSourceRefreshCannotOutrunRetainedCertificateProvenance(t *testing.T) {
	at := time.Unix(1800000000, 0).UTC()
	spec := seedSpec{Project: "task11-acceptance", ECDNS: "ec.task11.test", RSADNS: "rsa.task11.test", ServerDNS: "radius.task11.test", ECDB: "postgresql://stepca:synthetic@10.203.11.11/stepca?sslmode=verify-full", RSADB: "postgresql://stepca:synthetic@10.203.11.11/stepca_rsa?sslmode=verify-full", ObservedAt: at}
	files, err := generateSeed(spec)
	if err != nil {
		t.Fatal(err)
	}
	original := files["source/etc/freeradius/3.0/device-policy-cache.json"]
	retained := files["source/var/lib/cloud-8021x/certificate-state.json"]
	proof, err := deriveSourceProvenance(original, retained)
	if err != nil {
		t.Fatal(err)
	}
	if err = validateBoundSourceCache(original, proof); err != nil {
		t.Fatal(err)
	}
	decode := func() domain.Snapshot {
		s, e := domain.DecodeSnapshot(bytes.NewReader(original))
		if e != nil {
			t.Fatal(e)
		}
		return s
	}
	tests := map[string]func(*domain.Snapshot){
		"identity-device":     func(s *domain.Snapshot) { s.Identities[syntheticDevice].DeviceID = "fleet:999" },
		"identity-group":      func(s *domain.Snapshot) { s.Identities[syntheticDevice].Groups = []domain.GroupID{"fleet:999"} },
		"identity-unenrolled": func(s *domain.Snapshot) { s.Identities[syntheticDevice].Enrolled = false },
		"replacement-leaf": func(s *domain.Snapshot) {
			for fp, r := range s.Certificates {
				delete(s.Certificates, fp)
				s.Certificates[strings.Repeat("a", 64)] = r
				break
			}
		},
		"fresh-certificate-observation": func(s *domain.Snapshot) {
			v := domain.Unix(at.Add(time.Hour))
			for _, r := range s.Certificates {
				r.ObservedAt = &v
			}
			s.Identities[syntheticDevice].ObservedAt = &v
			s.UpdatedAt = v
		},
		"fresh-inventory": func(s *domain.Snapshot) { s.UpdatedAt = domain.Unix(at.Add(time.Second)) },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			s := decode()
			mutate(&s)
			raw, e := json.Marshal(s)
			if e != nil {
				t.Fatal(e)
			}
			if validateBoundSourceCache(raw, proof) == nil {
				t.Fatal("cache advanced or diverged without approved retained provenance")
			}
		})
	}
	// Explicit stale-inventory negative remains possible, but cannot alter the
	// original certificate/identity observation or ever advance its freshness.
	stale := decode()
	stale.UpdatedAt = domain.Unix(at.Add(-48 * time.Hour))
	b, err := json.Marshal(stale)
	if err != nil {
		t.Fatal(err)
	}
	if err = validateBoundSourceCache(b, proof); err != nil {
		t.Fatalf("explicit stale negative unavailable: %v", err)
	}
	changed := decode()
	changed.UpdatedAt = domain.Unix(at.Add(time.Hour))
	for _, r := range changed.Certificates {
		v := changed.UpdatedAt
		r.ObservedAt = &v
	}
	changed.Identities[syntheticDevice].ObservedAt = &changed.UpdatedAt
	b, err = json.Marshal(changed)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = deriveSourceProvenance(b, retained); err == nil {
		t.Fatal("root projection accepted unrelated original observation")
	}
}
