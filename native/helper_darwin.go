//go:build darwin

package native

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"time"
)

// The signed bundle archives are part of the module: go get requires no native
// compilation or downloads. Keep signatures intact across module zip extraction.
//
//go:embed assets/*.zip
var bundles embed.FS

func privateDir(path string) error {
	if err := os.Mkdir(path, 0700); err != nil && !os.IsExist(err) {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || info.Mode().Perm() != 0700 || st.Uid != uint32(os.Getuid()) {
		return errors.New("native cache must be an owned private directory")
	}
	return nil
}

func materialize(ctx context.Context) (string, error) {
	data, err := bundles.ReadFile("assets/darwin-" + runtime.GOARCH + ".zip")
	if err != nil {
		return "", err
	}
	base, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	if err = os.MkdirAll(base, 0700); err != nil {
		return "", err
	}
	// Do not chmod or replace caller-owned parent directories.
	root := filepath.Join(base, "dev.joshlane.intent")
	if err = privateDir(root); err != nil {
		return "", err
	}
	hash := sha256.Sum256(data)
	dest := filepath.Join(root, hex.EncodeToString(hash[:]))
	// Serialize across applications. Never follow a substituted lock symlink.
	fd, err := syscall.Open(filepath.Join(root, "install.lock"), syscall.O_CREAT|syscall.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return "", err
	}
	lock := os.NewFile(uintptr(fd), "intent native cache lock")
	defer lock.Close()
	st, err := lock.Stat()
	if err != nil {
		return "", err
	}
	owner, ok := st.Sys().(*syscall.Stat_t)
	if !ok || !st.Mode().IsRegular() || st.Mode().Perm() != 0600 || owner.Uid != uint32(os.Getuid()) {
		return "", errors.New("invalid native cache lock")
	}
	for {
		err = syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			break
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) {
			return "", err
		}
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(20 * time.Millisecond):
		}
	}
	if err = ctx.Err(); err != nil {
		return "", err
	}
	defer syscall.Flock(fd, syscall.LOCK_UN)
	archive, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return "", err
	}
	if err = verifyBundle(dest, archive); err != nil {
		// Preserve unexpected or tampered entries rather than recursively removing
		// content that may belong to another process. A new cache root repairs it.
		if _, e := os.Lstat(dest); !os.IsNotExist(e) {
			return "", fmt.Errorf("native cache integrity: %w", err)
		}
		stage, e := os.MkdirTemp(root, ".install-")
		if e != nil {
			return "", e
		}
		defer os.RemoveAll(stage)
		for _, f := range archive.File {
			if !filepath.IsLocal(f.Name) || f.Mode()&os.ModeSymlink != 0 {
				return "", errors.New("invalid embedded bundle path")
			}
			target := filepath.Join(stage, f.Name)
			if f.FileInfo().IsDir() {
				if e = os.MkdirAll(target, 0700); e != nil {
					return "", e
				}
				continue
			}
			if f.UncompressedSize64 > 8<<20 {
				return "", errors.New("embedded helper file too large")
			}
			if e = os.MkdirAll(filepath.Dir(target), 0700); e != nil {
				return "", e
			}
			r, e := f.Open()
			if e != nil {
				return "", e
			}
			content, e := io.ReadAll(io.LimitReader(r, 8<<20+1))
			r.Close()
			if e != nil {
				return "", e
			}
			mode := os.FileMode(0600)
			if f.Mode()&0111 != 0 {
				mode = 0700
			}
			if e = os.WriteFile(target, content, mode); e != nil {
				return "", e
			}
		}
		if e = verifyBundle(stage, archive); e != nil {
			return "", e
		}
		if e = os.Rename(stage, dest); e != nil {
			return "", e
		}
	}
	return filepath.Join(dest, "Intent.app", "Contents", "MacOS", "Intent"), nil
}

func verifyBundle(root string, archive *zip.Reader) error {
	if err := privateExisting(root, true); err != nil {
		return err
	}
	expected := map[string]bool{".": true}
	for _, f := range archive.File {
		if !filepath.IsLocal(f.Name) || f.Mode()&os.ModeSymlink != 0 {
			return errors.New("invalid bundle entry")
		}
		path := filepath.Join(root, f.Name)
		expected[filepath.Clean(f.Name)] = true
		for parent := filepath.Dir(filepath.Clean(f.Name)); parent != "."; parent = filepath.Dir(parent) {
			expected[parent] = true
		}
		if err := privateExisting(path, f.FileInfo().IsDir()); err != nil {
			return err
		}
		if f.FileInfo().IsDir() {
			continue
		}
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		mode := os.FileMode(0600)
		if f.Mode()&0111 != 0 {
			mode = 0700
		}
		if info.Mode().Perm() != mode {
			return errors.New("unexpected helper permissions")
		}
		r, err := f.Open()
		if err != nil {
			return err
		}
		want, err := io.ReadAll(io.LimitReader(r, 8<<20+1))
		r.Close()
		if err != nil {
			return err
		}
		if info.Size() != int64(len(want)) {
			return errors.New("helper size mismatch")
		}
		got, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if !bytes.Equal(got, want) {
			return errors.New("helper contents mismatch")
		}
	}
	return filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		if !expected[rel] {
			return errors.New("unexpected helper bundle entry")
		}
		return privateExisting(path, d.IsDir())
	})
}
func privateExisting(path string, dir bool) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != uint32(os.Getuid()) || info.Mode()&os.ModeSymlink != 0 || (dir && (!info.IsDir() || info.Mode().Perm() != 0700)) || (!dir && (!info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0)) {
		return errors.New("unsafe helper cache entry")
	}
	return nil
}
