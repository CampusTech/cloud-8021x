package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
)

// This helper plans and verifies. It has no write-to-image operation.
const gptSector = int64(512)
const gptTableBytes = 128 * 128

type gptPatch struct {
	Offset int64  `json:"offset"`
	Before []byte `json:"before"`
	After  []byte `json:"after"`
}
type gptPlan struct {
	BootSHA256      string     `json:"boot_sha256"`
	UnchangedSHA256 string     `json:"unchanged_ranges_sha256"`
	Patches         []gptPatch `json:"patches"`
	SourceSHA256    string     `json:"source_sha256"`
	ResultSHA256    string     `json:"planned_result_sha256"`
	SourceGUIDs     []string   `json:"source_guids"`
	BootGUIDs       []string   `json:"boot_guids"`
	ResultGUIDs     []string   `json:"result_guids"`
}
type gptLayout struct {
	headers       [2][]byte
	tables        [2][]byte
	headerOffsets [2]int64
	tableOffsets  [2]int64
	used          []int
	guids         [][16]byte
}

func readGPTBytes(r io.ReaderAt, offset int64, n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := r.ReadAt(b, offset)
	return b, err
}
func parseGPT(r io.ReaderAt, size int64) (gptLayout, error) {
	var g gptLayout
	if size < 68*gptSector || size > 8000000000 || size%gptSector != 0 {
		return g, errors.New("unsupported image size")
	}
	m, err := readGPTBytes(r, 0, 512)
	if err != nil {
		return g, err
	}
	sectors := uint64(size / 512)
	if m[510] != 0x55 || m[511] != 0xaa || m[450] != 0xee || binary.LittleEndian.Uint32(m[454:]) != 1 || uint64(binary.LittleEndian.Uint32(m[458:])) != sectors-1 || !bytes.Equal(m[462:510], make([]byte, 48)) {
		return g, errors.New("protective MBR required; hybrid layout refused")
	}
	g.headerOffsets = [2]int64{512, size - 512}
	g.tableOffsets = [2]int64{1024, size - 512 - gptTableBytes}
	for i := range 2 {
		h, e := readGPTBytes(r, g.headerOffsets[i], 512)
		if e != nil {
			return g, e
		}
		g.headers[i] = h
		if string(h[:8]) != "EFI PART" || binary.LittleEndian.Uint32(h[8:]) != 0x10000 || binary.LittleEndian.Uint32(h[12:]) != 92 || binary.LittleEndian.Uint32(h[20:]) != 0 {
			return g, errors.New("unsupported GPT header")
		}
		c := bytes.Clone(h[:92])
		want := binary.LittleEndian.Uint32(c[16:])
		clear(c[16:20])
		if crc32.ChecksumIEEE(c) != want {
			return g, errors.New("GPT header CRC mismatch")
		}
		if binary.LittleEndian.Uint64(h[24:]) != uint64(g.headerOffsets[i]/512) || binary.LittleEndian.Uint64(h[32:]) != uint64(g.headerOffsets[1-i]/512) || binary.LittleEndian.Uint64(h[72:]) != uint64(g.tableOffsets[i]/512) || binary.LittleEndian.Uint32(h[80:]) != 128 || binary.LittleEndian.Uint32(h[84:]) != 128 {
			return g, errors.New("GPT locations or bounded entry layout mismatch")
		}
		tab, e := readGPTBytes(r, g.tableOffsets[i], gptTableBytes)
		if e != nil {
			return g, e
		}
		g.tables[i] = tab
		if crc32.ChecksumIEEE(tab) != binary.LittleEndian.Uint32(h[88:]) {
			return g, errors.New("GPT table CRC mismatch")
		}
	}
	if !bytes.Equal(g.tables[0], g.tables[1]) || !bytes.Equal(g.headers[0][40:72], g.headers[1][40:72]) {
		return g, errors.New("GPT primary/backup disagreement")
	}
	first, last := binary.LittleEndian.Uint64(g.headers[0][40:]), binary.LittleEndian.Uint64(g.headers[0][48:])
	if first < 34 || first > last || last >= uint64(g.tableOffsets[1]/512) {
		return g, errors.New("invalid usable GPT range")
	}
	var disk [16]byte
	copy(disk[:], g.headers[0][56:72])
	g.guids = append(g.guids, disk)
	seen := map[[16]byte]bool{{}: true, disk: true}
	if disk == [16]byte{} {
		return g, errors.New("zero disk GUID")
	}
	var ranges [][2]uint64
	for n := range 128 {
		entry := g.tables[0][n*128 : (n+1)*128]
		if bytes.Equal(entry[:16], make([]byte, 16)) {
			if !bytes.Equal(entry, make([]byte, 128)) {
				return g, errors.New("nonzero unused GPT entry")
			}
			continue
		}
		var id [16]byte
		copy(id[:], entry[16:32])
		if seen[id] {
			return g, errors.New("zero or duplicate unique GUID")
		}
		seen[id] = true
		start, end := binary.LittleEndian.Uint64(entry[32:]), binary.LittleEndian.Uint64(entry[40:])
		if start < first || end > last || start > end {
			return g, errors.New("partition outside usable range")
		}
		for _, prior := range ranges {
			if start <= prior[1] && end >= prior[0] {
				return g, errors.New("overlapping partitions")
			}
		}
		ranges = append(ranges, [2]uint64{start, end})
		g.used = append(g.used, n)
		g.guids = append(g.guids, id)
	}
	if len(g.used) == 0 {
		return g, errors.New("no GPT partitions")
	}
	return g, nil
}
func gptGUID(id [16]byte) string {
	return fmt.Sprintf("%08x-%04x-%04x-%x-%x", binary.LittleEndian.Uint32(id[:4]), binary.LittleEndian.Uint16(id[4:6]), binary.LittleEndian.Uint16(id[6:8]), id[8:10], id[10:])
}
func gptGUIDStrings(ids [][16]byte) []string {
	out := make([]string, len(ids))
	for i, id := range ids {
		out[i] = gptGUID(id)
	}
	return out
}
func gptFields(g gptLayout) map[int64]int {
	fields := map[int64]int{}
	for i := range 2 {
		for off, n := range map[int64]int{16: 4, 56: 16, 88: 4} {
			fields[g.headerOffsets[i]+off] = n
		}
		for _, entry := range g.used {
			fields[g.tableOffsets[i]+int64(entry*128+16)] = 16
		}
	}
	return fields
}
func planGPT(source, boot io.ReaderAt, sourceSize, bootSize int64, random io.Reader) (gptPlan, error) {
	var p gptPlan
	g, err := parseGPT(source, sourceSize)
	if err != nil {
		return p, err
	}
	bootLayout, err := parseGPT(boot, bootSize)
	if err != nil {
		return p, err
	}
	p.SourceGUIDs = gptGUIDStrings(g.guids)
	p.BootGUIDs = gptGUIDStrings(bootLayout.guids)
	seen := map[[16]byte]bool{{}: true}
	for _, id := range append(append([][16]byte{}, g.guids...), bootLayout.guids...) {
		seen[id] = true
	}
	ids := make([][16]byte, len(g.guids))
	for i := range ids {
		if _, err = io.ReadFull(random, ids[i][:]); err != nil {
			return p, err
		}
		ids[i][7] = (ids[i][7] & 15) | 0x40
		ids[i][8] = (ids[i][8] & 63) | 0x80
		if seen[ids[i]] {
			return p, errors.New("generated GUID collision")
		}
		seen[ids[i]] = true
	}
	p.ResultGUIDs = gptGUIDStrings(ids)
	for i := range 2 {
		h, tab := bytes.Clone(g.headers[i]), bytes.Clone(g.tables[i])
		copy(h[56:72], ids[0][:])
		for j, entry := range g.used {
			copy(tab[entry*128+16:entry*128+32], ids[j+1][:])
		}
		binary.LittleEndian.PutUint32(h[88:], crc32.ChecksumIEEE(tab))
		clear(h[16:20])
		binary.LittleEndian.PutUint32(h[16:], crc32.ChecksumIEEE(h[:92]))
		for off, n := range map[int64]int{16: 4, 56: 16, 88: 4} {
			p.Patches = append(p.Patches, gptPatch{g.headerOffsets[i] + off, bytes.Clone(g.headers[i][off : off+int64(n)]), bytes.Clone(h[off : off+int64(n)])})
		}
		for _, entry := range g.used {
			off := entry*128 + 16
			p.Patches = append(p.Patches, gptPatch{g.tableOffsets[i] + int64(off), bytes.Clone(g.tables[i][off : off+16]), bytes.Clone(tab[off : off+16])})
		}
	}
	sort.Slice(p.Patches, func(i, j int) bool { return p.Patches[i].Offset < p.Patches[j].Offset })
	p.SourceSHA256, p.ResultSHA256, err = gptCompareStream(source, nil, sourceSize, p.Patches)
	if err != nil {
		return p, err
	}
	p.BootSHA256, _, err = gptCompareStream(boot, nil, bootSize, nil)
	if err != nil {
		return p, err
	}
	p.UnchangedSHA256, err = unchangedGPTHash(source, sourceSize, p.Patches)
	return p, err
}

// Compare the complete stream, replacing only independently allowlisted fields.
// One MiB working buffers avoid loading a multi-GiB evidence image into memory.
func gptCompareStream(source, derivative io.ReaderAt, size int64, patches []gptPatch) (string, string, error) {
	originalHash, resultHash := sha256.New(), sha256.New()
	buf := make([]byte, 1<<20)
	actual := make([]byte, 1<<20)
	for off := int64(0); off < size; off += int64(len(buf)) {
		n := int(min(int64(len(buf)), size-off))
		block := buf[:n]
		if _, err := source.ReadAt(block, off); err != nil {
			return "", "", err
		}
		_, _ = originalHash.Write(block)
		for _, p := range patches {
			end := p.Offset + int64(len(p.Before))
			lo, hi := max(off, p.Offset), min(off+int64(n), end)
			if lo >= hi {
				continue
			}
			left, right := lo-p.Offset, hi-p.Offset
			if !bytes.Equal(block[lo-off:hi-off], p.Before[left:right]) {
				return "", "", errors.New("source patch bytes changed")
			}
			copy(block[lo-off:hi-off], p.After[left:right])
		}
		_, _ = resultHash.Write(block)
		if derivative != nil {
			if _, err := derivative.ReadAt(actual[:n], off); err != nil {
				return "", "", err
			}
			if !bytes.Equal(block, actual[:n]) {
				return "", "", fmt.Errorf("derivative differs from exact planned bytes in block %d", off)
			}
		}
	}
	return hex.EncodeToString(originalHash.Sum(nil)), hex.EncodeToString(resultHash.Sum(nil)), nil
}
func verifyGPT(source, derivative, boot io.ReaderAt, size, bootSize int64, p gptPlan) error {
	bootLayout, err := parseGPT(boot, bootSize)
	if err != nil {
		return err
	}
	if !equalGPTStrings(gptGUIDStrings(bootLayout.guids), p.BootGUIDs) {
		return errors.New("fresh boot GUID inventory mismatch")
	}
	bootHash, _, err := gptCompareStream(boot, nil, bootSize, nil)
	if err != nil || bootHash != p.BootSHA256 {
		return errors.New("fresh boot hash mismatch")
	}
	g, err := parseGPT(source, size)
	if err != nil {
		return err
	}
	fields := gptFields(g)
	if len(fields) != len(p.Patches) {
		return errors.New("wrong GPT patch count")
	}
	for _, patch := range p.Patches {
		n, ok := fields[patch.Offset]
		if !ok || len(patch.Before) != n || len(patch.After) != n {
			return errors.New("patch outside exact GUID/CRC fields")
		}
		delete(fields, patch.Offset)
	}
	result, err := parseGPT(derivative, size)
	if err != nil {
		return err
	}
	if !equalGPTStrings(gptGUIDStrings(g.guids), p.SourceGUIDs) || !equalGPTStrings(gptGUIDStrings(result.guids), p.ResultGUIDs) {
		return errors.New("GUID inventory mismatch")
	}
	forbidden := map[string]bool{}
	for _, s := range append(append([]string{}, p.SourceGUIDs...), p.BootGUIDs...) {
		forbidden[s] = true
	}
	for _, s := range p.ResultGUIDs {
		if forbidden[s] {
			return errors.New("attachment GUID collision")
		}
	}
	a, b, err := gptCompareStream(source, derivative, size, p.Patches)
	if err != nil {
		return err
	}
	if a != p.SourceSHA256 || b != p.ResultSHA256 {
		return errors.New("full-stream hash mismatch")
	}
	rest, err := unchangedGPTHash(source, size, p.Patches)
	if err != nil || rest != p.UnchangedSHA256 {
		return errors.New("unchanged-range hash mismatch")
	}
	return nil
}
func unchangedGPTHash(r io.ReaderAt, size int64, patches []gptPatch) (string, error) {
	h := sha256.New()
	offset := int64(0)
	for _, patch := range patches {
		if patch.Offset < offset || patch.Offset+int64(len(patch.Before)) > size {
			return "", errors.New("unsorted or out-of-range patch")
		}
		if _, err := io.Copy(h, io.NewSectionReader(r, offset, patch.Offset-offset)); err != nil {
			return "", err
		}
		offset = patch.Offset + int64(len(patch.Before))
	}
	if _, err := io.Copy(h, io.NewSectionReader(r, offset, size-offset)); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
func equalGPTStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
func openGPTInput(path, expected string) (*os.File, error) {
	return openGPTPinned(path, expected, 68*512, 8000000000)
}
func openGPTPinned(path, expected string, minimum, maximum int64) (*os.File, error) {
	canonical, err := filepath.EvalSymlinks(path)
	if err != nil {
		return nil, err
	}
	if canonical != path || !strings.HasPrefix(path, "/private/tmp/cloud8021x-task11-") && !strings.HasPrefix(path, "/tmp/cloud8021x-task11-") {
		return nil, errors.New("owned canonical temporary path required")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	s, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || s.Uid != uint32(os.Getuid()) || info.Size() < minimum || info.Size() > maximum {
		return nil, errors.New("bounded owned regular input required")
	}
	if len(expected) != 64 {
		return nil, errors.New("SHA256 pin required")
	}
	if _, err = hex.DecodeString(expected); err != nil {
		return nil, err
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	opened, err := f.Stat()
	if err != nil || !os.SameFile(info, opened) {
		_ = f.Close()
		return nil, errors.New("input changed while opening")
	}
	h := sha256.New()
	_, err = io.Copy(h, io.LimitReader(f, maximum+1))
	if err != nil || hex.EncodeToString(h.Sum(nil)) != expected {
		_ = f.Close()
		return nil, errors.New("input hash mismatch")
	}
	return f, nil
}
func distinctGPTInputs(a, b *os.File) error {
	aa, err := a.Stat()
	if err != nil {
		return err
	}
	bb, err := b.Stat()
	if err != nil {
		return err
	}
	if os.SameFile(aa, bb) {
		return errors.New("input inode alias")
	}
	return nil
}
