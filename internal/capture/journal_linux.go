package capture

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

func secureDirectory(path string, mode os.FileMode) error {
	if err := os.Mkdir(path, mode); err != nil && !os.IsExist(err) {
		return err
	}
	return verifyDirectory(path, mode)
}

func verifyDirectory(path string, mode os.FileMode) error {
	s, err := os.Lstat(path)
	if err != nil {
		return err
	}
	st, ok := s.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != uint32(os.Geteuid()) || !s.IsDir() || s.Mode().Perm() != mode {
		return errors.New("capture: runtime directory has unsafe ownership or permissions")
	}
	return nil
}

func saveJournal(dir string, l ruleLease) error {
	if err := l.validate(l.UID); err != nil {
		return err
	}
	b, err := json.Marshal(l)
	if err != nil {
		return err
	}
	if len(b) > maxFrame {
		return errors.New("capture: ownership journal is too large")
	}
	f, err := os.CreateTemp(dir, ".pending-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(b); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err := os.Rename(f.Name(), filepath.Join(dir, l.ID+".json")); err != nil {
		return err
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

func readJournal(path string, uid int) (l ruleLease, err error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return l, err
	}
	defer f.Close()
	s, err := f.Stat()
	if err != nil {
		return l, err
	}
	st, ok := s.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != uint32(os.Geteuid()) || !s.Mode().IsRegular() || s.Mode().Perm() != 0600 || s.Size() > maxFrame {
		return l, errors.New("capture: unsafe ownership journal")
	}
	d := json.NewDecoder(io.LimitReader(f, maxFrame+1))
	d.DisallowUnknownFields()
	if err := d.Decode(&l); err != nil {
		return l, err
	}
	if d.Decode(new(any)) != io.EOF {
		return l, errors.New("capture: trailing journal data")
	}
	if err := l.validate(uid); err != nil {
		return l, err
	}
	if filepath.Base(path) != l.ID+".json" {
		return l, errors.New("capture: journal filename mismatch")
	}
	return l, nil
}
