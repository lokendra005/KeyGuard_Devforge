package guard

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
)

func readFile(path string, limit int64) ([]byte, os.FileInfo, error) {
	f, e := os.Open(path)
	if e != nil {
		return nil, nil, e
	}
	defer f.Close()
	info, e := f.Stat()
	if e != nil {
		return nil, nil, e
	}
	if !info.Mode().IsRegular() || info.Size() > limit {
		return nil, nil, errors.New("file is not regular or exceeds size limit")
	}
	b, e := io.ReadAll(io.LimitReader(f, limit+1))
	if e != nil {
		return nil, nil, e
	}
	if int64(len(b)) > limit {
		return nil, nil, errors.New("file exceeds size limit")
	}
	return b, info, nil
}
func ReadFile(path string, limit int64) ([]byte, error) {
	b, _, e := readFile(path, limit)
	return b, e
}
func ReadJSON(path string, v any) error {
	b, e := ReadFile(path, 64<<20)
	if e != nil {
		return e
	}
	return StrictJSON(b, v)
}
func ReadKey(path string) (KeyFile, error) {
	var k KeyFile
	b, info, e := readFile(path, 64<<10)
	if e != nil {
		return k, e
	}
	if e = StrictJSON(b, &k); e != nil {
		return k, e
	}
	if !identifier.MatchString(k.Subject) || !validPublic(k.Public) {
		return k, errors.New("invalid key file")
	}
	if len(k.Private) > 0 {
		if info.Mode().Perm()&0077 != 0 {
			return k, errors.New("private key file must have mode 0600")
		}
		if _, e = k.Sign([]byte("key check"), "KIG/keycheck/v1"); e != nil {
			return k, e
		}
	}
	return k, nil
}

// WriteJSON persists via fsync + rename; no successful witness acknowledgement precedes durability.
func WriteJSON(path string, v any, replace bool) error {
	b, e := json.MarshalIndent(v, "", "  ")
	if e != nil {
		return e
	}
	return WriteFile(path, append(b, '\n'), replace)
}
func WriteFile(path string, b []byte, replace bool) error {
	if !replace {
		if _, e := os.Lstat(path); e == nil {
			return errors.New("refusing to overwrite " + path)
		} else if !os.IsNotExist(e) {
			return e
		}
	}
	dir := filepath.Dir(path)
	f, e := os.CreateTemp(dir, ".kig-*")
	if e != nil {
		return e
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if _, e = f.Write(b); e != nil {
		f.Close()
		return e
	}
	if e = f.Sync(); e != nil {
		f.Close()
		return e
	}
	if e = f.Close(); e != nil {
		return e
	}
	if replace {
		e = os.Rename(tmp, path)
	} else {
		e = os.Link(tmp, path)
	}
	if e != nil {
		return e
	}
	d, e := os.Open(dir)
	if e != nil {
		return e
	}
	defer d.Close()
	return d.Sync()
}
