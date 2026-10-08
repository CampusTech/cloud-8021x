package stepca

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// This test uses separate OS processes as two nodes and filesystem-backed fake
// typed cloud/journal stores. The first publisher exits immediately after the
// first component publication; no process heap/root signing key survives.
func TestCASecondProcessRecoversAfterFirstComponentAndRootKeyLoss(t *testing.T) {
	directory := t.TempDir()
	kms, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := x509.MarshalPKCS8PrivateKey(kms)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(directory, "fixture-kms-intermediate"), key, 0600); err != nil {
		t.Fatal(err)
	}
	node := func(crash bool) error {
		command := exec.Command(os.Args[0], "-test.run=^TestCAPublicationProcessNode$")
		command.Env = append(os.Environ(), "C8021X_CA_PROCESS="+directory)
		if crash {
			command.Env = append(command.Env, "C8021X_CA_CRASH=first-component")
		}
		output, err := command.CombinedOutput()
		if !crash && err != nil {
			t.Fatalf("second node: %s %v", output, err)
		}
		return err
	}
	var exited *exec.ExitError
	if err = node(true); !errors.As(err, &exited) || exited.ExitCode() != 73 {
		t.Fatalf("publisher did not crash at first component: %v", err)
	}
	secrets := processSecrets{directory: directory}
	rootBefore, err := secrets.Access(context.Background(), "root/versions/1")
	if err != nil {
		t.Fatal(err)
	}
	stagedBefore, err := secrets.Access(context.Background(), "staging/versions/1")
	if err != nil {
		t.Fatal(err)
	}
	var material Material
	if err = json.Unmarshal(stagedBefore, &material); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(rootBefore, material.Root) {
		t.Fatal("first irreversible publication differs from durable original bundle")
	}
	if _, err = secrets.Access(context.Background(), "intermediate/versions/1"); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("crash happened after readiness publication")
	}
	_ = node(false)
	rootAfter, _ := secrets.Access(context.Background(), "root/versions/1")
	stagedAfter, _ := secrets.Access(context.Background(), "staging/versions/1")
	if !bytes.Equal(rootBefore, rootAfter) || !bytes.Equal(stagedBefore, stagedAfter) {
		t.Fatal("second node changed root trust or original private SCEP pair")
	}
	journal := processJournal{directory: directory}
	publication, err := journal.Load(context.Background(), "")
	if err != nil || !publication.Published {
		t.Fatal("second node did not finish original publication", err)
	}
}
func TestCAPublicationProcessNode(t *testing.T) {
	directory := os.Getenv("C8021X_CA_PROCESS")
	if directory == "" {
		t.Skip("subprocess fixture only")
	}
	keyBytes, err := os.ReadFile(filepath.Join(directory, "fixture-kms-intermediate"))
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(keyBytes)
	if err != nil {
		t.Fatal(err)
	}
	signer, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatal("fixture intermediate signer type")
	}
	manager := Manager{Store: processSecrets{directory: directory}, Journal: &processJournal{directory: directory}, Gate: &serialGate{}}
	if _, err = manager.Ensure(context.Background(), definition(), signer); err != nil {
		t.Fatal(err)
	}
}

type processSecrets struct{ directory string }

func (s processSecrets) path(name string) string {
	sum := sha256.Sum256([]byte(name))
	return filepath.Join(s.directory, "secret-"+hex.EncodeToString(sum[:]))
}
func (s processSecrets) Enabled(_ context.Context, name string) ([]string, error) {
	_, err := os.Stat(s.path(name))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return []string{name + "/versions/1"}, nil
}
func (s processSecrets) Access(_ context.Context, version string) ([]byte, error) {
	return os.ReadFile(s.path(strings.TrimSuffix(version, "/versions/1")))
}
func (s processSecrets) Add(_ context.Context, name string, value []byte) (string, error) {
	if _, err := os.Stat(s.path(name)); err == nil {
		return "", errors.New("fixture refuses replacement of original version")
	}
	if err := processPersist(s.path(name), value); err != nil {
		return "", err
	}
	if name == "root" && os.Getenv("C8021X_CA_CRASH") == "first-component" {
		os.Exit(73)
	}
	return name + "/versions/1", nil
}

type processJournal struct{ directory string }

func (j *processJournal) Load(context.Context, string) (Publication, error) {
	var value Publication
	data, err := os.ReadFile(filepath.Join(j.directory, "public-journal"))
	if errors.Is(err, os.ErrNotExist) {
		return value, nil
	}
	if err != nil {
		return value, err
	}
	err = json.Unmarshal(data, &value)
	return value, err
}
func (j *processJournal) write(value Publication) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return processPersist(filepath.Join(j.directory, "public-journal"), data)
}
func (j *processJournal) Begin(_ context.Context, _ string, p Publication) error { return j.write(p) }
func (j *processJournal) Bind(ctx context.Context, reference, version string) error {
	p, err := j.Load(ctx, reference)
	if err != nil {
		return err
	}
	p.Version = version
	return j.write(p)
}
func (j *processJournal) Published(ctx context.Context, reference string) error {
	p, err := j.Load(ctx, reference)
	if err != nil {
		return err
	}
	p.Published = true
	return j.write(p)
}
func processPersist(path string, data []byte) error {
	f, err := os.OpenFile(path+".next", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	err = errors.Join(err, f.Close())
	if err != nil {
		return err
	}
	if err = os.Rename(path+".next", path); err != nil {
		return err
	}
	directory, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer func() { _ = directory.Close() }()
	return directory.Sync()
}
