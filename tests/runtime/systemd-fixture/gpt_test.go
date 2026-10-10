package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"hash/crc32"
	"os"
	"path/filepath"
	"testing"
)

// Independent small, complete GPT image: 256 sectors, one data partition.
// Deliberately populated filesystem bytes expose accidental non-GPT changes.
func testGPTImage() []byte {
	b := bytes.Repeat([]byte{0xa5}, 256*512)
	clear(b[:34*512])
	clear(b[223*512:])
	b[510] = 0x55
	b[511] = 0xaa
	b[450] = 0xee
	binary.LittleEndian.PutUint32(b[454:], 1)
	binary.LittleEndian.PutUint32(b[458:], 255)
	entry := b[1024:1152]
	entry[0] = 0x11
	entry[16] = 0x22
	binary.LittleEndian.PutUint64(entry[32:], 34)
	binary.LittleEndian.PutUint64(entry[40:], 222)
	copy(b[223*512:255*512], b[1024:34*512])
	for _, spec := range [][3]uint64{{1, 255, 2}, {255, 1, 223}} {
		h := b[spec[0]*512 : (spec[0]+1)*512]
		copy(h, "EFI PART")
		binary.LittleEndian.PutUint32(h[8:], 0x10000)
		binary.LittleEndian.PutUint32(h[12:], 92)
		binary.LittleEndian.PutUint64(h[24:], spec[0])
		binary.LittleEndian.PutUint64(h[32:], spec[1])
		binary.LittleEndian.PutUint64(h[40:], 34)
		binary.LittleEndian.PutUint64(h[48:], 222)
		h[56] = 0x33
		binary.LittleEndian.PutUint64(h[72:], spec[2])
		binary.LittleEndian.PutUint32(h[80:], 128)
		binary.LittleEndian.PutUint32(h[84:], 128)
		binary.LittleEndian.PutUint32(h[88:], crc32.ChecksumIEEE(b[1024:34*512]))
		binary.LittleEndian.PutUint32(h[16:], crc32.ChecksumIEEE(h[:92]))
	}
	return b
}
func testGPTRecheck(b []byte) {
	for _, lba := range []int{1, 255} {
		h := b[lba*512 : (lba+1)*512]
		table := binary.LittleEndian.Uint64(h[72:]) * 512
		binary.LittleEndian.PutUint32(h[88:], crc32.ChecksumIEEE(b[table:table+16384]))
		clear(h[16:20])
		binary.LittleEndian.PutUint32(h[16:], crc32.ChecksumIEEE(h[:92]))
	}
}
func testGPTRandom() *bytes.Reader {
	return bytes.NewReader(bytes.Repeat([]byte{0x71, 0x82, 0x93, 0xa4, 0xb5, 0xc6, 0xd7, 0xe8, 0x19, 0x2a, 0x3b, 0x4c, 0x5d, 0x6e, 0x7f, 0x80, 0x91}, 64))
}
func TestGPTPlanChangesOnlyGUIDAndCRCFields(t *testing.T) {
	src := testGPTImage()
	original := bytes.Clone(src)
	plan, err := planGPT(bytes.NewReader(src), bytes.NewReader(src), int64(len(src)), int64(len(src)), testGPTRandom())
	if err != nil {
		t.Fatal(err)
	}
	derivative := bytes.Clone(src)
	for _, p := range plan.Patches {
		if !bytes.Equal(derivative[p.Offset:p.Offset+int64(len(p.Before))], p.Before) {
			t.Fatal("wrong before bytes")
		}
		copy(derivative[p.Offset:], p.After)
	}
	if bytes.Equal(src, derivative) {
		t.Fatal("duplicate identities not replaced")
	}
	// Hand-derived writable byte ranges for the one-partition test fixture.
	allowed := [][2]int{{528, 532}, {568, 584}, {600, 604}, {1040, 1056}, {114192, 114208}, {130576, 130580}, {130616, 130632}, {130648, 130652}}
	for i := range src {
		if src[i] != derivative[i] {
			ok := false
			for _, r := range allowed {
				ok = ok || (i >= r[0] && i < r[1])
			}
			if !ok {
				t.Fatalf("changed forbidden byte %d", i)
			}
		}
	}
	if !bytes.Equal(src, original) {
		t.Fatal("planner mutated source")
	}
	for _, off := range []int{568, 1040} {
		if bytes.Equal(src[off:off+16], derivative[off:off+16]) {
			t.Fatal("identity unchanged")
		}
	}
	if !bytes.Equal(derivative[1040:1056], derivative[114192:114208]) {
		t.Fatal("partition GUID copies differ")
	}
	for _, lba := range []int{1, 255} {
		h := bytes.Clone(derivative[lba*512 : lba*512+92])
		want := binary.LittleEndian.Uint32(h[16:])
		clear(h[16:20])
		if crc32.ChecksumIEEE(h) != want {
			t.Fatal("bad header CRC")
		}
		table := binary.LittleEndian.Uint64(h[72:]) * 512
		if crc32.ChecksumIEEE(derivative[table:table+16384]) != binary.LittleEndian.Uint32(h[88:]) {
			t.Fatal("bad table CRC")
		}
	}
	if err := verifyGPT(bytes.NewReader(src), bytes.NewReader(derivative), bytes.NewReader(src), int64(len(src)), int64(len(src)), plan); err != nil {
		t.Fatal(err)
	}
	derivative[100*512] ^= 1
	if err := verifyGPT(bytes.NewReader(src), bytes.NewReader(derivative), bytes.NewReader(src), int64(len(src)), int64(len(src)), plan); err == nil {
		t.Fatal("filesystem mutation accepted")
	}
}
func TestGPTRejectsMalformedInputs(t *testing.T) {
	cases := map[string]func([]byte){
		"primary-crc": func(b []byte) { b[528] ^= 1 }, "backup-crc": func(b []byte) { b[130576] ^= 1 },
		"table-crc": func(b []byte) { b[1050] ^= 1 }, "backup-table": func(b []byte) { b[114200] ^= 1; testGPTRecheck(b) },
		"backup-location": func(b []byte) { binary.LittleEndian.PutUint64(b[544:], 254); testGPTRecheck(b) },
		"table-overflow":  func(b []byte) { binary.LittleEndian.PutUint32(b[592:], 0xffffffff); testGPTRecheck(b) },
		"partition-outside": func(b []byte) {
			binary.LittleEndian.PutUint64(b[1064:], 223)
			copy(b[223*512:255*512], b[1024:34*512])
			testGPTRecheck(b)
		},
		"hybrid-mbr": func(b []byte) { b[466] = 0x83 },
		"duplicate-partition": func(b []byte) {
			copy(b[1152:1280], b[1024:1152])
			copy(b[223*512:255*512], b[1024:34*512])
			testGPTRecheck(b)
		},
		"reserved-header": func(b []byte) { b[532] = 1; testGPTRecheck(b) },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			b := testGPTImage()
			mutate(b)
			if _, err := planGPT(bytes.NewReader(b), bytes.NewReader(testGPTImage()), int64(len(b)), int64(len(b)), testGPTRandom()); err == nil {
				t.Fatal("malformed GPT accepted")
			}
		})
	}
	t.Run("short-image", func(t *testing.T) {
		b := testGPTImage()
		if _, err := planGPT(bytes.NewReader(b[:512]), bytes.NewReader(b), int64(len(b)), int64(len(b)), testGPTRandom()); err == nil {
			t.Fatal("short read accepted")
		}
	})
	t.Run("entropy-failure", func(t *testing.T) {
		b := testGPTImage()
		if _, err := planGPT(bytes.NewReader(b), bytes.NewReader(b), int64(len(b)), int64(len(b)), bytes.NewReader(nil)); err == nil {
			t.Fatal("missing entropy accepted")
		}
	})
}
func TestGPTInputGuards(t *testing.T) {
	root, err := filepath.EvalSymlinks("/tmp")
	if err != nil {
		t.Fatal(err)
	}
	dir, err := os.MkdirTemp(root, "cloud8021x-task11-gpt-test-")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.RemoveAll(dir) }()
	a := filepath.Join(dir, "source.img")
	b := testGPTImage()
	if err := os.WriteFile(a, b, 0600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(b)
	digest := hex.EncodeToString(sum[:])
	f, err := openGPTInput(a, digest)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	if _, err := openGPTInput(a, "0000000000000000000000000000000000000000000000000000000000000000"); err == nil {
		t.Fatal("wrong source admitted")
	}
	link := filepath.Join(dir, "link.img")
	if err := os.Symlink(a, link); err != nil {
		t.Fatal(err)
	}
	if _, err := openGPTInput(link, digest); err == nil {
		t.Fatal("symlink admitted")
	}
	hard := filepath.Join(dir, "hard.img")
	if err := os.Link(a, hard); err != nil {
		t.Fatal(err)
	}
	g, err := openGPTInput(hard, digest)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = g.Close() }()
	if err := distinctGPTInputs(f, g); err == nil {
		t.Fatal("hardlink alias admitted")
	}
	if _, err := f.WriteAt([]byte{0}, 0); err == nil {
		t.Fatal("source writable")
	}
}

func TestGPTRejectsTamperedPlan(t *testing.T) {
	for _, kind := range []string{"filesystem-patch", "missing-patch", "source-hash", "result-hash", "boot-collision"} {
		t.Run(kind, func(t *testing.T) {
			b := testGPTImage()
			p, err := planGPT(bytes.NewReader(b), bytes.NewReader(b), int64(len(b)), int64(len(b)), testGPTRandom())
			if err != nil {
				t.Fatal(err)
			}
			d := bytes.Clone(b)
			for _, patch := range p.Patches {
				copy(d[patch.Offset:], patch.After)
			}
			switch kind {
			case "filesystem-patch":
				p.Patches[0] = gptPatch{100 * 512, []byte{0xa5}, []byte{0xbb}}
				d[100*512] = 0xbb
			case "missing-patch":
				p.Patches = p.Patches[1:]
			case "source-hash":
				p.SourceSHA256 = "untrusted"
			case "result-hash":
				p.ResultSHA256 = "untrusted"
			case "boot-collision":
				p.BootGUIDs = append(p.BootGUIDs, p.ResultGUIDs[0])
			}
			if err := verifyGPT(bytes.NewReader(b), bytes.NewReader(d), bytes.NewReader(b), int64(len(b)), int64(len(b)), p); err == nil {
				t.Fatal("tampered plan admitted")
			}
		})
	}
}
func TestGPTCommandIsReadOnlyAndPinned(t *testing.T) {
	root, err := filepath.EvalSymlinks("/tmp")
	if err != nil {
		t.Fatal(err)
	}
	dir, err := os.MkdirTemp(root, "cloud8021x-task11-gpt-command-")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.RemoveAll(dir) }()
	data := testGPTImage()
	sum := sha256.Sum256(data)
	pin := hex.EncodeToString(sum[:])
	a, b := filepath.Join(dir, "source.img"), filepath.Join(dir, "boot.img")
	for _, path := range []string{a, b} {
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	var output bytes.Buffer
	cmd := gptCommand()
	cmd.SetOut(&output)
	cmd.SetArgs([]string{"--source", a, "--source-sha256", pin, "--boot", b, "--boot-sha256", pin})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(output.Bytes(), []byte(`"planned_result_sha256"`)) {
		t.Fatal("no reviewable plan")
	}
	for _, path := range []string{a, b} {
		actual, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(actual, data) {
			t.Fatal("command changed input")
		}
	}
	cmd = gptCommand()
	cmd.SetArgs([]string{"--source", a, "--source-sha256", pin, "--boot", a, "--boot-sha256", pin})
	if err := cmd.Execute(); err == nil {
		t.Fatal("aliased command inputs accepted")
	}
}
