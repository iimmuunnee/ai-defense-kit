// Package safeio writes output files without following links that someone
// else may have planted at the destination.
package safeio

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
)

// ErrNotRegular is wrapped in the error returned when the destination exists
// and is a link, a folder, a FIFO or anything else that is not a regular file.
var ErrNotRegular = errors.New("일반 파일이 아니라 쓰지 않습니다")

// beforeRename runs between the last write and the rename. Tests set it to
// change the destination at that moment; it is not part of the API.
var beforeRename = func(string) {}

// Check reports whether path may be written: it must not exist or must be a
// regular file. WriteFile makes the same check, so a caller with several
// files to write can check them all before writing any.
func Check(path string) error {
	_, err := check(path)
	return err
}

func check(path string) (fs.FileInfo, error) {
	fi, err := os.Lstat(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nil, nil
	case err != nil:
		return nil, fmt.Errorf("%s: 대상을 확인하지 못했습니다: %w", path, err)
	case !fi.Mode().IsRegular():
		return nil, fmt.Errorf("%s: %w", path, ErrNotRegular)
	}
	return fi, nil
}

func createTemp(dir string, perm os.FileMode) (*os.File, error) {
	for range 100 {
		var b [8]byte
		if _, err := rand.Read(b[:]); err != nil {
			return nil, err
		}
		name := filepath.Join(dir, ".adk-"+hex.EncodeToString(b[:])+".tmp")
		f, err := os.OpenFile(name, os.O_RDWR|os.O_CREATE|os.O_EXCL, perm)
		if !errors.Is(err, fs.ErrExist) {
			return f, err
		}
	}
	return nil, fmt.Errorf("%s: 임시 파일 이름을 정하지 못했습니다", dir)
}

// WriteFile writes path only when it does not exist or is a regular file. fn
// writes into a temp file in the same folder, which replaces path by rename
// once it is complete, so a failed write leaves the old file as it was. A link
// at path is refused, never followed. A link as the parent folder is not
// refused: that is a folder the user chose.
//
// A new file gets perm as the system's umask leaves it. A file that is
// replaced keeps the mode it had.
func WriteFile(path string, perm os.FileMode, fn func(io.Writer) error) (err error) {
	old, err := check(path)
	if err != nil {
		return err
	}
	f, err := createTemp(filepath.Dir(path), perm)
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer func() {
		if err != nil {
			os.Remove(tmp)
		}
	}()
	if err = fn(f); err != nil {
		f.Close()
		return err
	}
	if old != nil {
		if err = f.Chmod(old.Mode().Perm()); err != nil {
			f.Close()
			return err
		}
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	beforeRename(path)
	// os.Rename replaces an existing file on Windows as well, and replaces a
	// link planted after the check instead of following it.
	return os.Rename(tmp, path)
}

// openAppend opens path for appending without following a link or waiting on
// a FIFO, and refuses what it opened if it is not a regular file.
func openAppend(path string, perm os.FileMode) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY|openFlags, perm)
	if err != nil {
		return nil, err
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		f.Close()
		return nil, fmt.Errorf("%s: %w", path, ErrNotRegular)
	}
	return f, nil
}

// AppendFile appends data to an append-only file. It cannot go through a temp
// file and rename, so the destination is checked first and, where the system
// allows, opened without following a link and checked again once open.
func AppendFile(path string, perm os.FileMode, data []byte) error {
	if err := Check(path); err != nil {
		return err
	}
	f, err := openAppend(path, perm)
	if err != nil {
		return err
	}
	_, werr := f.Write(data)
	serr := f.Sync()
	return errors.Join(werr, serr, f.Close())
}
