//go:build !windows

// Package approvaldiscovery maps an sshd-provided connection identity to a
// private endpoint receipt. It carries no credentials or approval decisions.
package approvaldiscovery

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/lanej/intent/internal/cleanup"
)

type Receipt struct {
	Version int    `json:"version"`
	Session string `json:"session"`
	Socket  string `json:"socket"`
}

func PrivateDir(path string, create bool) error {
	if create {
		if err := os.MkdirAll(path, 0o700); err != nil {
			return err
		}
	}

	info, err := os.Lstat(path)
	if err != nil {
		return err
	}

	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || info.Mode().Perm() != 0o700 || int64(stat.Uid) != int64(os.Getuid()) {
		return fmt.Errorf("path is not a private owned directory: %s", path)
	}

	return nil
}

func receiptPath(create bool) (string, error) {
	path, err := Path()
	if err != nil {
		return "", err
	}

	if err = PrivateDir(filepath.Dir(path), create); err != nil {
		return "", err
	}

	return path, nil
}

// Path snapshots the sshd connection identity before asynchronous setup ends.
func Path() (string, error) {
	connection := os.Getenv("SSH_CONNECTION")
	if len(strings.Fields(connection)) != 4 {
		return "", errors.New("no SSH approval endpoint; connect with Intent SSH configuration or set INTENT_APPROVAL_SOCKET")
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	// Keep this independent of OS-specific cache/config paths so both callers
	// and the remote helper derive the same location, even without shell rc files.
	dir := filepath.Join(home, ".intent-approval")
	hash := sha256.Sum256([]byte(connection))

	return filepath.Join(dir, hex.EncodeToString(hash[:])+".json"), nil
}

func Publish(receipt Receipt) error {
	return PublishWithCleanup(receipt, nil)
}

// PublishWithCleanup serializes registry mutation across remote helper
// processes. Cleanup may inspect/prune old records while client reads remain
// lock-free; it must not recursively publish or remove registry entries.
func PublishWithCleanup(receipt Receipt, cleanup func() error) error {
	// Existing explicit-launcher use outside SSH needs no discovery receipt.
	if os.Getenv("SSH_CONNECTION") == "" {
		return nil
	}

	return withRegistryLock(func() error {
		if cleanup != nil {
			if err := cleanup(); err != nil {
				return err
			}
		}

		return publish(receipt)
	})
}

func publish(receipt Receipt) error {
	path, err := receiptPath(true)
	if err != nil {
		return err
	}

	data, err := json.Marshal(receipt)
	if err != nil {
		return err
	}

	f, err := os.CreateTemp(filepath.Dir(path), ".receipt-")
	if err != nil {
		return err
	}
	defer cleanup.Remove(f.Name())

	if _, err = f.Write(data); err != nil {
		cleanup.Close(f)
		return err
	}

	if err = f.Close(); err != nil {
		return err
	}

	return os.Rename(f.Name(), path)
}

func Read() (Receipt, error) {
	path, err := receiptPath(false)
	if err != nil {
		return Receipt{}, err
	}

	return ReadPath(path)
}

func ReadPath(path string) (Receipt, error) {
	var r Receipt
	if err := PrivateDir(filepath.Dir(path), false); err != nil {
		return r, err
	}

	info, err := os.Lstat(path)
	if err != nil {
		return r, err
	}

	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || int64(stat.Uid) != int64(os.Getuid()) || info.Size() > 4096 {
		return r, errors.New("invalid SSH approval receipt")
	}

	data, err := os.ReadFile(path) // #nosec G304 -- The receipt or registry lock is inside an owned private directory and validated before use.
	if err != nil {
		return r, err
	}

	if err = json.Unmarshal(data, &r); err != nil || r.Version != 1 || r.Session == "" || !filepath.IsAbs(r.Socket) {
		return Receipt{}, errors.New("invalid SSH approval receipt")
	}

	return r, nil
}

func Remove(session string) error {
	if os.Getenv("SSH_CONNECTION") == "" {
		return nil
	}

	return withRegistryLock(func() error { return remove(session) })
}

func remove(session string) error {
	path, err := receiptPath(false)
	if os.IsNotExist(err) {
		return nil
	}

	if err != nil {
		return err
	}

	r, err := Read()
	if os.IsNotExist(err) {
		return nil
	}

	if err != nil {
		return err
	}

	if r.Session != session {
		return nil
	} // A later connection owns this receipt.

	return os.Remove(path)
}

func withRegistryLock(mutate func() error) error {
	path, err := receiptPath(true)
	if err != nil {
		return err
	}

	lockPath := filepath.Join(filepath.Dir(path), "registry.lock")

	file, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0o600) // #nosec G304 -- The receipt or registry lock is inside an owned private directory and validated before use.
	if err != nil {
		return err
	}
	defer cleanup.Close(file)

	info, err := file.Stat()
	if err != nil {
		return err
	}

	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || int64(stat.Uid) != int64(os.Getuid()) {
		return errors.New("registry lock is not a private owned file")
	}

	if err = syscall.Flock(int(file.Fd()), syscall.LOCK_EX); err != nil {
		return err
	}

	defer cleanup.Unlock(int(file.Fd()))

	return mutate()
}
