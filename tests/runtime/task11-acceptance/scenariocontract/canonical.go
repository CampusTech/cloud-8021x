package scenariocontract

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"strings"

	"github.com/CampusTech/cloud-8021x/internal/domain"
)

var errCanonicalJSON = errors.New("canonical declared JSON members required")

// decodeCanonicalJSON adds exact member spelling to the production strict decoder.
// It never normalizes keys or reconstructs opaque business payloads.
func decodeCanonicalJSON(raw []byte, destination any) error {
	if e := domain.DecodeJSONStrict(raw, destination); e != nil {
		return e
	}
	t := reflect.TypeOf(destination)
	if t == nil || t.Kind() != reflect.Pointer {
		return errCanonicalJSON
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if e := canonicalValue(dec, t.Elem(), 0); e != nil {
		return errCanonicalJSON
	}
	if _, e := dec.Token(); !errors.Is(e, io.EOF) {
		return errCanonicalJSON
	}
	return nil
}

func canonicalType(t reflect.Type) reflect.Type {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	return t
}

func canonicalFields(t reflect.Type) map[string]reflect.Type {
	fields := map[string]reflect.Type{}
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if f.PkgPath != "" {
			continue
		}
		name, _, _ := strings.Cut(f.Tag.Get("json"), ",")
		if name == "-" {
			continue
		}
		if name == "" && f.Anonymous && canonicalType(f.Type).Kind() == reflect.Struct {
			for key, fieldType := range canonicalFields(canonicalType(f.Type)) {
				fields[key] = fieldType
			}
			continue
		}
		if name == "" {
			name = f.Name
		}
		fields[name] = f.Type
	}
	return fields
}

func canonicalValue(dec *json.Decoder, t reflect.Type, depth int) error {
	if depth > 64 {
		return errCanonicalJSON
	}
	token, e := dec.Token()
	if e != nil {
		return errCanonicalJSON
	}
	delim, compound := token.(json.Delim)
	if !compound {
		// The strict decoder already validates scalar/custom JSON values (time.Time)
		// and base64 []byte. Their contents are not transport member names.
		return nil
	}
	t = canonicalType(t)
	switch delim {
	case '{':
		var fields map[string]reflect.Type
		if t.Kind() == reflect.Struct {
			fields = canonicalFields(t)
		} else if t.Kind() != reflect.Map || t.Key().Kind() != reflect.String {
			return errCanonicalJSON
		}
		for dec.More() {
			key, e := dec.Token()
			name, ok := key.(string)
			if e != nil || !ok {
				return errCanonicalJSON
			}
			var member reflect.Type
			if t.Kind() == reflect.Map {
				member = t.Elem()
			} else if member, ok = fields[name]; !ok {
				return errCanonicalJSON
			}
			if e := canonicalValue(dec, member, depth+1); e != nil {
				return e
			}
		}
		end, e := dec.Token()
		if e != nil || end != json.Delim('}') {
			return errCanonicalJSON
		}
	case '[':
		if (t.Kind() != reflect.Slice && t.Kind() != reflect.Array) || (t.Kind() == reflect.Slice && t.Elem().Kind() == reflect.Uint8) {
			return errCanonicalJSON
		}
		for dec.More() {
			if e := canonicalValue(dec, t.Elem(), depth+1); e != nil {
				return e
			}
		}
		end, e := dec.Token()
		if e != nil || end != json.Delim(']') {
			return errCanonicalJSON
		}
	default:
		return errCanonicalJSON
	}
	return nil
}
