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

	"github.com/lanej/intent/internal/cleanup"
)

// The signed bundle archives are part of the module: go get requires no native
// compilation or downloads. Keep signatures intact across module zip extraction.
//
//go:embed assets/*.zip
var bundles embed.FS

func privateDir(path string) error {
	if err := os.Mkdir(path, 0o700); err != nil && !os.IsExist(err) {
		return err
	}

	info, err := os.Lstat(path)
	if err != nil {
		return err
	}

	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || info.Mode().Perm() != 0o700 || int64(st.Uid) != int64(os.Getuid()) {
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

	if err = os.MkdirAll(base, 0o700); err != nil {
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
	fd, err := syscall.Open(filepath.Join(root, "install.lock"), syscall.O_CREAT|syscall.O_RDWR|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return "", err
	}

	lock := os.NewFile(uintptr(fd), "intent native cache lock")
	defer cleanup.Close(lock)

	st, err := lock.Stat()
	if err != nil {
		return "", err
	}

	owner, ok := st.Sys().(*syscall.Stat_t)
	if !ok || !st.Mode().IsRegular() || st.Mode().Perm() != 0o600 || int64(owner.Uid) != int64(os.Getuid()) {
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

	defer cleanup.Unlock(fd)

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
		defer cleanup.RemoveAll(stage)

		for _, f := range archive.File {
			if !filepath.IsLocal(f.Name) || f.Mode()&os.ModeSymlink != 0 {
				return "", errors.New("invalid embedded bundle path")
			}

			target := filepath.Join(stage, f.Name) // #nosec G305 -- Embedded archive names pass IsLocal and symlink checks before joining the private root.
			if f.FileInfo().IsDir() {
				if e = os.MkdirAll(target, 0o700); e != nil {
					return "", e
				}

				continue
			}

			if f.UncompressedSize64 > 8<<20 {
				return "", errors.New("embedded helper file too large")
			}

			if e = os.MkdirAll(filepath.Dir(target), 0o700); e != nil {
				return "", e
			}

			r, openErr := f.Open()
			if openErr != nil {
				return "", openErr
			}

			content, openErr := io.ReadAll(io.LimitReader(r, 8<<20+1))
			cleanup.Close(r)

			if openErr != nil {
				return "", openErr
			}

			mode := os.FileMode(0o600)
			if f.Mode()&0o111 != 0 {
				mode = 0o700
			}

			if openErr = os.WriteFile(target, content, mode); openErr != nil {
				return "", openErr
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

		path := filepath.Join(root, f.Name) // #nosec G305 -- Embedded archive names pass IsLocal and symlink checks before joining the private root.

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

		mode := os.FileMode(0o600)
		if f.Mode()&0o111 != 0 {
			mode = 0o700
		}

		if info.Mode().Perm() != mode {
			return errors.New("unexpected helper permissions")
		}

		r, err := f.Open()
		if err != nil {
			return err
		}

		want, err := io.ReadAll(io.LimitReader(r, 8<<20+1))
		cleanup.Close(r)

		if err != nil {
			return err
		}

		if info.Size() != int64(len(want)) {
			return errors.New("helper size mismatch")
		}

		got, err := os.ReadFile(path) // #nosec G304 -- The content-addressed helper path is checked for ownership, permissions, and embedded-byte integrity.
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
	if !ok || int64(st.Uid) != int64(os.Getuid()) || info.Mode()&os.ModeSymlink != 0 || (dir && (!info.IsDir() || info.Mode().Perm() != 0o700)) || (!dir && (!info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0)) {
		return errors.New("unsafe helper cache entry")
	}

	return nil
}
