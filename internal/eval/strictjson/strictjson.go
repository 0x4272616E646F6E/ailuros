package strictjson

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
)

func Decode(line []byte, v any) error {
	if err := checkKeys(line, reflect.TypeOf(v)); err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(line))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if dec.InputOffset() != int64(len(line)) {
		return errors.New("unexpected data after the JSON object")
	}
	return nil
}

func checkKeys(raw []byte, t reflect.Type) error {
	for t != nil && t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	raw = bytes.TrimSpace(raw)
	if t == nil || len(raw) == 0 {
		return nil
	}
	switch raw[0] {
	case '{':
		return checkObject(raw, t)
	case '[':
		if t.Kind() != reflect.Slice && t.Kind() != reflect.Array {
			return nil
		}
		var items []json.RawMessage
		if err := json.Unmarshal(raw, &items); err != nil {
			return nil
		}
		for _, it := range items {
			if err := checkKeys(it, t.Elem()); err != nil {
				return err
			}
		}
	}
	return nil
}

func checkObject(raw []byte, t reflect.Type) error {
	var fields map[string]reflect.Type
	if t.Kind() == reflect.Struct {
		fields = jsonFields(t)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	if _, err := dec.Token(); err != nil {
		return nil
	}
	seen := map[string]bool{}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil
		}
		key, _ := tok.(string)
		if seen[key] {
			return fmt.Errorf("duplicate key %q", key)
		}
		seen[key] = true
		var val json.RawMessage
		if err := dec.Decode(&val); err != nil {
			return nil
		}
		var elem reflect.Type
		switch t.Kind() {
		case reflect.Struct:
			ft, ok := fields[key]
			if !ok {
				return fmt.Errorf("unknown field %q (field names are lower-case)", key)
			}
			elem = ft
		case reflect.Map:
			elem = t.Elem()
		default:
			continue
		}
		if err := checkKeys(val, elem); err != nil {
			return err
		}
	}
	return nil
}

func jsonFields(t reflect.Type) map[string]reflect.Type {
	out := map[string]reflect.Type{}
	for f := range t.Fields() {
		if !f.IsExported() && !f.Anonymous {
			continue
		}
		tag := f.Tag.Get("json")
		name, _, _ := strings.Cut(tag, ",")
		if name == "-" {
			continue
		}
		if f.Anonymous && name == "" && f.Type.Kind() == reflect.Struct {
			for k, v := range jsonFields(f.Type) {
				out[k] = v
			}
			continue
		}
		if name == "" {
			name = f.Name
		}
		out[name] = f.Type
	}
	return out
}
