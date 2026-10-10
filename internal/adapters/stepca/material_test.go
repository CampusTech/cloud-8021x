package stepca

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"testing"
	"time"
)

type memorySecrets struct {
	values               map[string][]byte
	writes               []string
	listError, readError bool
	fail                 string
}

func (s *memorySecrets) Enabled(context.Context, string) ([]string, error) {
	if s.listError {
		return nil, errors.New("outage")
	}
	return nil, nil
}

type fixtureStore struct{ *memorySecrets }

func (s fixtureStore) Enabled(_ context.Context, n string) ([]string, error) {
	if s.listError {
		return nil, errors.New("outage")
	}
	if _, ok := s.values[n]; ok {
		return []string{n + "/versions/1"}, nil
	}
	return nil, nil
}
func (s fixtureStore) Access(_ context.Context, v string) ([]byte, error) {
	if s.readError {
		return nil, errors.New("denied")
	}
	return s.values[v[:len(v)-len("/versions/1")]], nil
}
func (s fixtureStore) Add(_ context.Context, n string, b []byte) (string, error) {
	s.writes = append(s.writes, n)
	if n == s.fail {
		return "", errors.New("uncertain")
	}
	s.values[n] = append([]byte(nil), b...)
	return n + "/versions/1", nil
}

type serialGate struct{ calls int }

func (s *serialGate) With(_ context.Context, _ string, f func(context.Context) error) error {
	s.calls++
	return f(context.Background())
}
func fixture(t *testing.T) (*Manager, fixtureStore, crypto.Signer) {
	t.Helper()
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	s := fixtureStore{&memorySecrets{values: map[string][]byte{}}}
	m := &Manager{Store: s, Gate: &serialGate{}, Now: time.Now, Journal: &memoryJournal{}}
	return m, s, key
}
func definition() Definition {
	return Definition{Kind: EC, StagingSecret: "staging", Name: "Fixture", RootSecret: "root", IntermediateSecret: "intermediate", DecrypterCertSecret: "decrypter-cert", DecrypterKeySecret: "decrypter-key"}
}
func TestAdoptionNeverReplacesExistingOrUnreadableCA(t *testing.T) {
	for _, mode := range []string{"list-outage", "read-outage", "partial", "invalid", "adopt"} {
		t.Run(mode, func(t *testing.T) {
			m, s, key := fixture(t)
			d := definition()
			if mode != "list-outage" {
				b, e := m.Ensure(context.Background(), d, key)
				if e != nil {
					t.Fatal(e)
				}
				if e = Validate(b, EC, key.Public(), time.Now()); e != nil {
					t.Fatal(e)
				}
			}
			s.writes = nil
			switch mode {
			case "list-outage":
				s.listError = true
			case "read-outage":
				s.readError = true
			case "partial":
				delete(s.values, "intermediate")
			case "invalid":
				s.values["root"] = []byte("bad")
			}
			_, e := m.Ensure(context.Background(), d, key)
			if (e == nil) != (mode == "adopt") {
				t.Fatalf("error=%v mode=%s", e, mode)
			}
			if len(s.writes) != 0 {
				t.Fatalf("replaced trust on %s", mode)
			}
		})
	}
}
func TestPublicationReadinessLastAndFailureClosed(t *testing.T) {
	for _, fail := range []string{"", "root", "decrypter-cert", "decrypter-key", "intermediate"} {
		t.Run(fail, func(t *testing.T) {
			m, s, key := fixture(t)
			s.fail = fail
			_, e := m.Ensure(context.Background(), definition(), key)
			if (e == nil) != (fail == "") {
				t.Fatalf("error=%v", e)
			}
			want := []string{"staging", "root", "decrypter-cert", "decrypter-key", "intermediate"}
			for i, n := range s.writes {
				if n != want[i] {
					t.Fatal(s.writes)
				}
			}
			if fail != "" && s.values["intermediate"] != nil {
				t.Fatal("published readiness despite failure")
			}
		})
	}
}
func TestMaterialRejectsWrongSignerAndSoftwareKey(t *testing.T) {
	m, _, key := fixture(t)
	b, e := m.Ensure(context.Background(), definition(), key)
	if e != nil {
		t.Fatal(e)
	}
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if Validate(b, EC, other.Public(), time.Now()) == nil {
		t.Fatal("wrong KMS signer accepted")
	}
	b.DecrypterKey = []byte("bad")
	if Validate(b, EC, key.Public(), time.Now()) == nil {
		t.Fatal("bad software key accepted")
	}
}

// A different process has no root signing key. Recovery must use the original
// complete durable bundle, never create replacement trust after publication.
func TestCrashAfterFirstPublicationRecoversOriginalMaterial(t *testing.T) {
	m, s, key := fixture(t)
	s.fail = "decrypter-cert"
	if _, err := m.Ensure(context.Background(), definition(), key); err == nil {
		t.Fatal("expected interrupted publication")
	}
	original := append([]byte(nil), s.values["root"]...)
	if len(original) == 0 {
		t.Fatal("crash did not occur after root publication")
	}
	s.fail = ""
	next := &Manager{Store: s, Gate: &serialGate{}, Journal: m.Journal}
	material, err := next.Ensure(context.Background(), definition(), key)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(original, material.Root) {
		t.Fatal("replaced root trust")
	}
	if len(s.writes) != 6 {
		t.Fatalf("rewrote published component: %v", s.writes)
	}
	if err := Validate(material, EC, key.Public(), time.Now()); err != nil {
		t.Fatal(err)
	}
}

type memoryJournal struct {
	value Publication
	fail  bool
}

func (j *memoryJournal) Load(context.Context, string) (Publication, error) {
	if j.fail {
		return Publication{}, errors.New("journal unavailable")
	}
	return j.value, nil
}
func (j *memoryJournal) Begin(_ context.Context, _ string, p Publication) error {
	if j.fail {
		return errors.New("journal unavailable")
	}
	if j.value.Secret != "" && j.value != p {
		return errors.New("immutable")
	}
	j.value = p
	return nil
}
func (j *memoryJournal) Bind(_ context.Context, _ string, v string) error {
	if j.value.Version != "" && j.value.Version != v {
		return errors.New("immutable")
	}
	j.value.Version = v
	return nil
}
func (j *memoryJournal) Published(context.Context, string) error {
	j.value.Published = true
	return nil
}

func TestJournalUnavailableNeverPublishes(t *testing.T) {
	m, s, key := fixture(t)
	m.Journal = &memoryJournal{fail: true}
	if _, e := m.Ensure(context.Background(), definition(), key); e == nil {
		t.Fatal("accepted unavailable journal")
	}
	if len(s.writes) != 0 {
		t.Fatal("published before durable recovery bundle")
	}
}

func TestCompleteCAFinishesOriginalPublicationJournal(t *testing.T) {
	m, s, key := fixture(t)
	original, err := m.Ensure(context.Background(), definition(), key)
	if err != nil {
		t.Fatal(err)
	}
	journal := m.Journal.(*memoryJournal)
	journal.value.Published = false
	s.writes = nil
	if _, err = m.Ensure(context.Background(), definition(), key); err != nil {
		t.Fatal(err)
	}
	if !journal.value.Published || len(s.writes) != 0 {
		t.Fatal("completed components did not finalize existing immutable publication")
	}
	if string(original.Root) != string(s.values[definition().RootSecret]) {
		t.Fatal("root changed")
	}
}
