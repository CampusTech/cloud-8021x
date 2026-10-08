package host

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestLegacyFenceQuiescenceRejectsUnknownAndActiveWriter(t *testing.T) {
	for _, output := range []string{"", "ActiveState=active\nSubState=running\nMainPID=3\n", "ActiveState=inactive\nSubState=dead\nMainPID=3\n"} {
		err := writerUnitsQuiescent(context.Background(), func(context.Context, string, ...string) ([]byte, error) { return []byte(output), nil }, legacyWriterUnits)
		if err == nil {
			t.Fatal("accepted unknown or active writer")
		}
	}
	if err := writerUnitsQuiescent(context.Background(), func(_ context.Context, path string, args ...string) ([]byte, error) {
		if path != "/usr/bin/systemctl" || !strings.HasSuffix(args[1], ".service") && !strings.HasSuffix(args[1], ".timer") {
			return nil, errors.New("unfixed probe")
		}
		return []byte("ActiveState=inactive\nSubState=dead\nMainPID=0\n"), nil
	}, legacyWriterUnits); err != nil {
		t.Fatal(err)
	}
}

func TestWriterReceiptRejectsIncompleteDuplicateAndForeignBeforeRestore(t *testing.T) {
	r := writerReceipt{Version: 1, Transition: strings.Repeat("a", 64), Node: "radius-primary", ConfigSHA256: strings.Repeat("b", 64)}
	for _, path := range legacyWriterPaths() {
		r.Files = append(r.Files, SavedFile{File: File{Path: path}})
	}
	raw, _ := json.Marshal(r)
	if _, err := decodeWriterReceipt(raw, r.Transition); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*writerReceipt){
		func(r *writerReceipt) { r.Files = r.Files[:len(r.Files)-1] },
		func(r *writerReceipt) { r.Files[1] = r.Files[0] },
		func(r *writerReceipt) { r.Files[len(r.Files)-1].Path = "/etc/shadow" },
		func(r *writerReceipt) { r.Files[0].Exists = true; r.Files[0].UID = 99 },
		func(r *writerReceipt) { r.Masks = []string{legacyWriterCrons[0]} },
		func(r *writerReceipt) { r.Files[0].Data = []byte("invented absent bytes") },
	} {
		var bad writerReceipt
		_ = json.Unmarshal(raw, &bad)
		mutate(&bad)
		b, _ := json.Marshal(bad)
		if _, err := decodeWriterReceipt(b, r.Transition); err == nil {
			t.Fatalf("accepted invalid receipt %s", b)
		}
	}
	duplicate := append([]byte(`{"Version":1,`), raw[1:]...)
	if _, err := decodeWriterReceipt(duplicate, r.Transition); err == nil {
		t.Fatal("duplicate key accepted")
	}
}
func TestVLANTailFencePreservesImportedLibrary(t *testing.T) {
	original := []byte("def cached_name():\n    return 'known'\n\nif __name__ == '__main__':\n    sys.exit(main())\n")
	got, err := inertVLANModule(original)
	if err != nil || !bytes.HasPrefix(got, []byte("def cached_name():\n    return 'known'\n")) || bytes.Contains(got, []byte("sys.exit(main())")) {
		t.Fatalf("library or CLI incorrect: %q %v", got, err)
	}
	for _, bad := range [][]byte{append(original, []byte("do_more()\n")...), []byte("if __name__ == '__main__':\n    arbitrary()\n"), append(original, original...)} {
		if _, err := inertVLANModule(bad); err == nil {
			t.Fatal("foreign tail accepted")
		}
	}
}
func TestWriterProcessTreeIncludesShellAndOrphanedObservedDescendants(t *testing.T) {
	initial := []writerProcess{{PID: 10, Start: 1, Args: "/bin/sh\x00-c\x00/usr/local/bin/fleet-device-fetch.sh foo\x00"}, {PID: 11, Parent: 10, Start: 2, Args: "curl\x00https://example.invalid\x00"}}
	evidence := writerProcessEvidence(initial)
	if len(evidence) != 2 {
		t.Fatal("lost shell writer or child", evidence)
	}
	if err := checkWriterProcesses([]writerProcess{{PID: 11, Parent: 1, Start: 2, Args: "curl\x00"}}, evidence); err == nil {
		t.Fatal("orphaned observed child allowed")
	}
	if err := checkWriterProcesses([]writerProcess{{PID: 11, Parent: 1, Start: 3, Args: "unrelated\x00"}}, evidence); err != nil {
		t.Fatal("PID reuse treated as same process", err)
	}
}

func TestWriterRecoveryRejectsChangedOriginalOrFinalState(t *testing.T) {
	original := SavedFile{File: File{Path: legacyWriterHelpers[0], Data: []byte("old"), Mode: 0755}, Exists: true}
	for _, now := range []SavedFile{original, {File: File{Path: original.Path, Data: inertHelper, Mode: 0755}, Exists: true}} {
		if e := validateRecoverableWriterFile(original, now); e != nil {
			t.Fatal(e)
		}
	}
	for _, now := range []SavedFile{{File: File{Path: original.Path, Data: []byte("foreign"), Mode: 0755}, Exists: true}, {File: File{Path: original.Path, Data: inertHelper, Mode: 0775}, Exists: true}, {File: File{Path: original.Path, Data: inertHelper, Mode: 0755, UID: 1001}, Exists: true}} {
		if e := validateRecoverableWriterFile(original, now); e == nil {
			t.Fatal("foreign recovery state accepted")
		}
	}
}
