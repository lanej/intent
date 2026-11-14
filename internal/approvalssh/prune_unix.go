//go:build !windows

package approvalssh

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/lanej/intent/internal/approvaldiscovery"
	"github.com/lanej/intent/internal/approvalwire"
)

// An SSH master can disappear before a cleanup channel can run. Subsequent
// setup repairs only owned receipts whose socket has no listening transport.
// Successful probes send no protocol bytes and cannot create approval prompts.
// The caller holds the discovery registry's mutation lock throughout this pass.
func pruneStaleApprovals() error {
	if os.Getenv("SSH_CONNECTION") == "" {
		return nil
	}
	path, err := approvaldiscovery.Path()
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err = approvaldiscovery.PrivateDir(dir, false); os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	deadline := time.Now().Add(time.Second)
	removed := 0
	for _, entry := range entries {
		if removed >= 64 || !time.Now().Before(deadline) {
			break
		}
		if filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		candidate := filepath.Join(dir, entry.Name())
		receipt, err := approvaldiscovery.ReadPath(candidate)
		if err != nil || !approvalwire.ValidID(receipt.Session) || !validRemoteSocket(receipt.Socket) {
			continue
		}
		if err = checkRemote(receipt.Session, receipt.Socket); os.IsNotExist(err) {
			// A missing directory is already clean, but its receipt can remain after
			// an interrupted cleanup. Re-read identity before removing the receipt.
			if _, e := os.Lstat(filepath.Dir(receipt.Socket)); !os.IsNotExist(e) {
				continue
			}
		} else if err != nil {
			continue
		} else {
			conn, e := net.DialTimeout("unix", receipt.Socket, 100*time.Millisecond)
			if e == nil {
				conn.Close()
				continue
			}
			if !errors.Is(e, syscall.ENOENT) && !errors.Is(e, syscall.ECONNREFUSED) {
				continue
			}
			if cleanupEndpoint(receipt.Session, receipt.Socket) != nil {
				continue
			}
		}
		current, err := approvaldiscovery.ReadPath(candidate)
		if err == nil && current == receipt {
			if err = os.Remove(candidate); err == nil {
				removed++
			}
		}
	}
	return nil
}
