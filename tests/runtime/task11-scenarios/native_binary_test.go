package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestNativeELFDescriptorPinsBytesBeforeChildExecution(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "owned-native-elf")
	raw := make([]byte, 64)
	copy(raw, []byte{0x7f, 'E', 'L', 'F', 2, 1, 1})
	raw[16] = 3
	raw[18] = 183
	if e := os.WriteFile(path, raw, 0755); e != nil {
		t.Fatal(e)
	}
	file, e := openNativeELFAt(path, digestBytes(raw), os.Geteuid())
	if e != nil {
		t.Fatal("retained executable guard absent", e)
	}
	defer func() { _ = file.Close() }()
	read := make([]byte, len(raw))
	if _, e = file.Read(read); e != nil || !bytes.Equal(read, raw) {
		t.Fatal("measured executable FD not rewound/retained")
	}
	for _, bad := range []string{"pin", "mode", "link", "arch", "symlink"} {
		t.Run(bad, func(t *testing.T) {
			target := filepath.Join(dir, bad)
			data := bytes.Clone(raw)
			pin := digestBytes(raw)
			if bad == "arch" {
				data[18] = 62
				pin = digestBytes(data)
			}
			if e := os.WriteFile(target, data, 0755); e != nil {
				t.Fatal(e)
			}
			switch bad {
			case "pin":
				pin = digestBytes([]byte("wrong"))
			case "mode":
				if e := os.Chmod(target, 0775); e != nil {
					t.Fatal(e)
				}
			case "link":
				if e := os.Link(target, target+"-alias"); e != nil {
					t.Fatal(e)
				}
			case "symlink":
				if e := os.Remove(target); e != nil {
					t.Fatal(e)
				}
				if e := os.Symlink(path, target); e != nil {
					t.Fatal(e)
				}
			}
			accepted, e := openNativeELFAt(target, pin, os.Geteuid())
			if accepted != nil {
				_ = accepted.Close()
			}
			if e == nil {
				t.Fatal("unmeasured/writable/foreign executable accepted")
			}
		})
	}
}
