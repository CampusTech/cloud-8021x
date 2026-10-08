package fleet

import (
	"bytes"
	"encoding/binary"
	"errors"
	"sort"
	"unicode/utf16"
	"unicode/utf8"

	"howett.net/plist"
)

// The maintained decoder preserves binary/XML compatibility, but its dictionary
// conversion collapses duplicate keys and it allocates from trailer counts. This
// bounded structural prevalidation checks the graph and every dictionary before
// handing data to it. It does not decode certificate/MDM semantics.
func decodeBinaryPlist(data []byte) (value any, err error) {
	defer func() {
		if recover() != nil {
			value = nil
			err = errors.New("invalid binary plist")
		}
	}()
	if err = validateBinaryPlist(data); err != nil {
		return nil, err
	}
	_, err = plist.Unmarshal(data, &value)
	if err != nil {
		return nil, errors.New("invalid binary plist")
	}
	return value, nil
}
func validateBinaryPlist(data []byte) error {
	invalid := errors.New("invalid, oversized or duplicate binary plist")
	if len(data) < 40 || len(data) > MaxResponseBytes || !bytes.Equal(data[:8], []byte("bplist00")) {
		return invalid
	}
	trailer := data[len(data)-32:]
	ow, rw := int(trailer[6]), int(trailer[7])
	validWidth := func(w int) bool { return w == 1 || w == 2 || w == 4 || w == 8 }
	if !validWidth(ow) || !validWidth(rw) {
		return invalid
	}
	count, top, table := binary.BigEndian.Uint64(trailer[8:16]), binary.BigEndian.Uint64(trailer[16:24]), binary.BigEndian.Uint64(trailer[24:32])
	if count == 0 || count > 4096 || top >= count || table < 8 || table >= uint64(len(data)-32) || count*uint64(ow) != uint64(len(data)-32)-table {
		return invalid
	}
	read := func(pos uint64, width int) (uint64, bool) {
		if !validWidth(width) || pos > uint64(len(data)) || uint64(width) > uint64(len(data))-pos {
			return 0, false
		}
		var v uint64
		for _, b := range data[pos : pos+uint64(width)] {
			v = (v << 8) | uint64(b)
		}
		return v, true
	}
	offsets := make([]uint64, count)
	for i := range count {
		v, ok := read(table+i*uint64(ow), ow)
		if !ok || v < 8 || v >= table {
			return invalid
		}
		offsets[i] = v
	}
	sorted := append([]uint64{}, offsets...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	ends := map[uint64]uint64{}
	for i, offset := range sorted {
		if i > 0 && sorted[i-1] == offset {
			return invalid
		}
		end := table
		if i+1 < len(sorted) {
			end = sorted[i+1]
		}
		ends[offset] = end
	}
	refs := make([][]uint64, count)
	keys := make(map[uint64]string)
	dictKeys := make(map[uint64][]uint64)
	for i, off := range offsets {
		tag := data[off]
		kind := tag >> 4
		n := uint64(tag & 15)
		start := off + 1
		end := ends[off]
		variable := kind == 4 || kind == 5 || kind == 6 || kind == 10 || kind == 13
		if variable && n == 15 {
			if start >= end || data[start]>>4 != 1 || data[start]&15 > 3 {
				return invalid
			}
			width := 1 << uint(data[start]&15)
			var ok bool
			n, ok = read(start+1, width)
			if !ok {
				return invalid
			}
			start += 1 + uint64(width)
			if n > 1<<20 {
				return invalid
			}
		}
		length := uint64(0)
		switch kind {
		case 0:
			if tag != 0x08 && tag != 0x09 {
				return invalid
			}
		case 1:
			if n > 3 {
				return invalid
			}
			length = 1 << n
		case 2:
			if n != 2 && n != 3 {
				return invalid
			}
			length = 1 << n
		case 3:
			if tag != 0x33 {
				return invalid
			}
			length = 8
		case 4:
			if n > 64<<10 {
				return invalid
			}
			length = n
		case 5:
			if n > 1<<20 {
				return invalid
			}
			length = n
		case 6:
			if n > 1<<19 {
				return invalid
			}
			length = n * 2
		case 10, 13:
			if n > 1024 {
				return invalid
			}
			length = n * uint64(rw)
			if kind == 13 {
				length *= 2
			}
		default:
			return invalid
		}
		if start > end || length > end-start {
			return invalid
		}
		if kind == 5 || kind == 6 {
			if kind == 5 {
				raw := data[start : start+length]
				for _, b := range raw {
					if b > 127 {
						return invalid
					}
				}
				keys[uint64(i)] = string(raw)
			} else {
				units := make([]uint16, n)
				for j := range n {
					units[j] = binary.BigEndian.Uint16(data[start+j*2 : start+j*2+2])
				}
				for j := 0; j < len(units); j++ {
					u := units[j]
					if u >= 0xd800 && u <= 0xdbff {
						if j+1 >= len(units) || units[j+1] < 0xdc00 || units[j+1] > 0xdfff {
							return invalid
						}
						j++
					} else if u >= 0xdc00 && u <= 0xdfff {
						return invalid
					}
				}
				text := string(utf16.Decode(units))
				if !utf8.ValidString(text) {
					return invalid
				}
				keys[uint64(i)] = text
			}
		}
		if kind == 10 || kind == 13 {
			refCount := n
			if kind == 13 {
				refCount *= 2
			}
			for j := range refCount {
				ref, ok := read(start+j*uint64(rw), rw)
				if !ok || ref >= count {
					return invalid
				}
				refs[i] = append(refs[i], ref)
			}
			if kind == 13 {
				dictKeys[uint64(i)] = refs[i][:n]
			}
		}
	}
	for _, dictionary := range dictKeys {
		seen := map[string]bool{}
		for _, key := range dictionary {
			text, ok := keys[key]
			if !ok || seen[text] {
				return invalid
			}
			seen[text] = true
		}
	}
	// Walk every object, including unreachable ones. Bound nesting and traversal so
	// shared-object graphs cannot cause exponential decoder work or stack growth.
	visits := 0
	var walk func(uint64, int, map[uint64]bool) bool
	walk = func(id uint64, depth int, stack map[uint64]bool) bool {
		visits++
		if visits > 65536 || depth > 16 || stack[id] {
			return false
		}
		stack[id] = true
		for _, child := range refs[id] {
			if !walk(child, depth+1, stack) {
				return false
			}
		}
		delete(stack, id)
		return true
	}
	for i := range count {
		if !walk(i, 0, map[uint64]bool{}) {
			return invalid
		}
	}
	return nil
}
