package guard

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
)

// Match the wire schema before encoding/json can accept case aliases, null scalars,
// or silently discard extra fixed-array elements. Optional fields may be omitted.
func jsonShape(raw json.RawMessage, typ reflect.Type) error {
	if typ == nil {
		return nil
	}
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		switch typ.Kind() {
		case reflect.Pointer, reflect.Interface, reflect.Map, reflect.Slice:
			return nil
		}
		return fmt.Errorf("null is not a %s", typ.Kind())
	}
	if typ.Kind() == reflect.Pointer {
		return jsonShape(raw, typ.Elem())
	}
	switch typ.Kind() {
	case reflect.Struct:
		var object map[string]json.RawMessage
		if e := json.Unmarshal(raw, &object); e != nil {
			return e
		}
		fields := map[string]reflect.Type{}
		for i := 0; i < typ.NumField(); i++ {
			f := typ.Field(i)
			if !f.IsExported() {
				continue
			}
			name := strings.Split(f.Tag.Get("json"), ",")[0]
			if name == "-" {
				continue
			}
			if name == "" {
				name = f.Name
			}
			fields[name] = f.Type
		}
		for name, v := range object {
			field, ok := fields[name]
			if !ok {
				return fmt.Errorf("unknown or noncanonical field %q", name)
			}
			if e := jsonShape(v, field); e != nil {
				return fmt.Errorf("%s: %w", name, e)
			}
		}
	case reflect.Array, reflect.Slice:
		if typ.Kind() == reflect.Slice && typ.Elem().Kind() == reflect.Uint8 {
			return nil
		}
		var values []json.RawMessage
		if e := json.Unmarshal(raw, &values); e != nil {
			return e
		}
		if typ.Kind() == reflect.Array && len(values) != typ.Len() {
			return fmt.Errorf("array requires exactly %d elements", typ.Len())
		}
		for _, v := range values {
			if e := jsonShape(v, typ.Elem()); e != nil {
				return e
			}
		}
	case reflect.Map:
		var values map[string]json.RawMessage
		if e := json.Unmarshal(raw, &values); e != nil {
			return e
		}
		for _, v := range values {
			if e := jsonShape(v, typ.Elem()); e != nil {
				return e
			}
		}
	}
	return nil
}
