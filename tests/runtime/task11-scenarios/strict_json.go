package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
)

// Standard decoding alone permits duplicate object keys. Private pinned inputs
// and public CA replies reject duplicates before typed unknown-field decoding.
func strictJSON(raw []byte, limit int, dst any) error {
	if len(raw) == 0 || len(raw) > limit {
		return errors.New("bounded JSON required")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	tokens := 0
	var walk func(int) error
	walk = func(depth int) error {
		tokens++
		if depth > 16 || tokens > 16384 {
			return errors.New("JSON nesting/token bound exceeded")
		}
		v, e := d.Token()
		if e != nil {
			return errors.New("incomplete JSON")
		}
		delimiter, ok := v.(json.Delim)
		if !ok {
			return nil
		}
		switch delimiter {
		case '{':
			seen := map[string]bool{}
			for d.More() {
				key, e := d.Token()
				if e != nil {
					return errors.New("invalid JSON object")
				}
				s, ok := key.(string)
				if !ok || seen[s] {
					return errors.New("duplicate JSON field")
				}
				seen[s] = true
				if e := walk(depth + 1); e != nil {
					return e
				}
			}
			end, e := d.Token()
			if e != nil || end != json.Delim('}') {
				return errors.New("incomplete JSON object")
			}
		case '[':
			count := 0
			for d.More() {
				count++
				if count > 256 {
					return errors.New("JSON array bound exceeded")
				}
				if e := walk(depth + 1); e != nil {
					return e
				}
			}
			end, e := d.Token()
			if e != nil || end != json.Delim(']') {
				return errors.New("incomplete JSON array")
			}
		default:
			return errors.New("invalid JSON delimiter")
		}
		return nil
	}
	if e := walk(0); e != nil {
		return e
	}
	if _, e := d.Token(); e != io.EOF {
		return errors.New("trailing JSON")
	}
	typed := json.NewDecoder(bytes.NewReader(raw))
	typed.DisallowUnknownFields()
	if e := typed.Decode(dst); e != nil {
		return errors.New("invalid typed JSON")
	}
	return nil
}
