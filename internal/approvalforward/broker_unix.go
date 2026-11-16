//go:build !windows

// Package approvalforward owns the stable remote endpoint and private transport routing.
package approvalforward

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/lanej/intent/internal/approvaldiscovery"
	"github.com/lanej/intent/internal/approvalwire"
	"github.com/lanej/intent/internal/cleanup"
)

// SocketPath rejects paths that cannot fit a pathname socket on both macOS and Linux.
func SocketPath(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || len(path) > 103 || strings.ContainsAny(path, "\x00\r\n") {
		return errors.New("socket must have a canonical absolute path of at most 103 bytes")
	}

	return nil
}

// Listen preserves live or unexpected endpoints. The caller holds its private directory lock.
func Listen(ctx context.Context, path string) (net.Listener, error) {
	if err := SocketPath(path); err != nil {
		return nil, err
	}

	if err := approvaldiscovery.PrivateDir(filepath.Dir(path), false); err != nil {
		return nil, err
	}

	if info, err := os.Lstat(path); err == nil {
		if !ownedSocket(info) {
			return nil, fmt.Errorf("preserve unexpected endpoint: %s", path)
		}

		conn, dialErr := (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "unix", path)
		if dialErr == nil {
			cleanup.Close(conn)
			return nil, errors.New("preserve live endpoint")
		}

		if !errors.Is(dialErr, syscall.ECONNREFUSED) {
			return nil, dialErr
		}

		if err = removeUnchanged(path, info); err != nil {
			return nil, err
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}

	listener, err := (&net.ListenConfig{}).Listen(ctx, "unix", path)
	if err != nil {
		return nil, err
	}

	unixListener, ok := listener.(*net.UnixListener)
	if !ok {
		cleanup.Close(listener)
		return nil, errors.New("unix listener required")
	}

	unixListener.SetUnlinkOnClose(false)

	info, statErr := os.Lstat(path)
	if statErr != nil {
		cleanup.Close(listener)
		return nil, statErr
	}

	if !ownedSocket(info) {
		cleanup.Close(listener)
		return nil, errors.New("endpoint changed during listener setup")
	}

	listener = &ownedListener{Listener: listener, path: path, info: info}
	if err = os.Chmod(path, 0o600); err != nil {
		cleanup.Close(listener)
		return nil, err
	}

	return listener, nil
}

// Go's default UnixListener.Close unlinks the pathname even if another inode
// replaced it. Own the cleanup explicitly so shutdown preserves replacements.
type ownedListener struct {
	net.Listener
	path string
	info os.FileInfo
	once sync.Once
	err  error
}

func (l *ownedListener) Close() error {
	l.once.Do(func() {
		l.err = l.Listener.Close()

		current, err := os.Lstat(l.path)
		if os.IsNotExist(err) {
			return
		}

		if err != nil {
			l.err = errors.Join(l.err, err)
			return
		}

		if os.SameFile(l.info, current) {
			l.err = errors.Join(l.err, os.Remove(l.path))
		}
	})

	return l.err
}

func ownedSocket(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && int64(stat.Uid) == int64(os.Getuid()) && info.Mode()&os.ModeSocket != 0
}

func removeUnchanged(path string, before os.FileInfo) error {
	current, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil
	}

	if err != nil {
		return err
	}

	if !os.SameFile(before, current) {
		return errors.New("endpoint changed during stale check")
	}

	return os.Remove(path)
}

// Lock serializes an Intent user service without following an existing symlink.
func Lock(dir, name string) (*os.File, error) {
	if filepath.Base(name) != name {
		return nil, errors.New("invalid lock name")
	}

	if err := approvaldiscovery.PrivateDir(dir, true); err != nil {
		return nil, err
	}

	file, err := os.OpenFile(filepath.Join(dir, name), os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0o600) // #nosec G304 -- The validated basename is inside a private owned directory; O_NOFOLLOW preserves symlinks.
	if err != nil {
		return nil, err
	}

	info, err := file.Stat()
	if err != nil {
		cleanup.Close(file)
		return nil, err
	}

	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || int64(stat.Uid) != int64(os.Getuid()) {
		cleanup.Close(file)
		return nil, errors.New("service lock is not private and owned")
	}

	if err = syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		cleanup.Close(file)
		return nil, err
	}

	return file, nil
}

// LockWait bounds contention during configuration without changing service singleton locks.
func LockWait(parent context.Context, dir, name string) (*os.File, error) {
	ctx, cancel := context.WithTimeout(parent, 3*time.Second)
	defer cancel()

	for {
		file, err := Lock(dir, name)
		if err == nil {
			return file, nil
		}

		if !errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, err
		}

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(10 * time.Millisecond):
		}
	}
}

// Probe sends an invalid request that cannot enter native authentication.
func Probe(parent context.Context, socket, id string) error {
	ctx, cancel := context.WithTimeout(parent, 200*time.Millisecond)
	defer cancel()

	conn, err := (&net.Dialer{}).DialContext(ctx, "unix", socket)
	if err != nil {
		return err
	}
	defer cleanup.Close(conn)

	stop := context.AfterFunc(ctx, func() { cleanup.Close(conn) })
	defer stop()

	deadline, _ := ctx.Deadline()
	if err = conn.SetDeadline(deadline); err != nil {
		return err
	}

	if err = json.NewEncoder(conn).Encode(approvalwire.Request{Version: approvalwire.Version, ID: id}); err != nil {
		return err
	}

	var response approvalwire.Response
	if err = approvalwire.Read(conn, &response); err != nil {
		return err
	}

	if response.Version != approvalwire.Version || response.ID != id || response.Decision != "" || response.Error != "invalid approval request or unsupported version" {
		return errors.New("unexpected approval readiness response")
	}

	return nil
}

// ServeRemote routes new calls to the newest live transport for the configured Mac.
// Once request bytes are forwarded, transport failure closes that call without replay.
func ServeRemote(parent context.Context, dir, mac string) error {
	if !filepath.IsAbs(dir) || filepath.Clean(dir) != dir || !approvalwire.ValidID(mac) {
		return errors.New("absolute private broker directory and valid Mac routing ID are required")
	}

	if err := SocketPath(filepath.Join(dir, mac+"-"+mac+".sock")); err != nil {
		return err
	}

	lock, err := Lock(dir, "broker.lock")
	if err != nil {
		return err
	}
	defer cleanup.Close(lock)

	listener, err := Listen(parent, filepath.Join(dir, "approval.sock"))
	if err != nil {
		return err
	}
	defer cleanup.Close(listener)

	ctx, cancel := context.WithCancel(parent)
	defer cancel()

	stop := context.AfterFunc(ctx, func() { cleanup.Close(listener) })
	defer stop()

	var handlers sync.WaitGroup

	handlers.Add(1)
	go func() { defer handlers.Done(); sweep(ctx, dir, mac) }()

	defer func() { cancel(); handlers.Wait() }()

	for {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			if ctx.Err() != nil {
				return nil
			}

			return acceptErr
		}

		handlers.Add(1)
		go func() { defer handlers.Done(); handle(ctx, conn, dir, mac) }()
	}
}

func handle(ctx context.Context, conn net.Conn, dir, mac string) {
	defer cleanup.Close(conn)

	stop := context.AfterFunc(ctx, func() { cleanup.Close(conn) })
	defer stop()

	if err := conn.SetDeadline(time.Now().Add(2 * time.Minute)); err != nil {
		return
	}

	routeCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	upstream, err := selectTransport(routeCtx, dir, mac)

	cancel()

	if err != nil {
		unavailable(conn)
		return
	}

	proxy(ctx, conn, upstream)
}

type candidate struct {
	path     string
	modified time.Time
	info     os.FileInfo
}

func transports(dir, mac string) ([]candidate, error) {
	file, err := os.Open(dir) // #nosec G304 -- The broker directory is canonical, private and owned.
	if err != nil {
		return nil, err
	}
	defer cleanup.Close(file)

	entries, err := file.ReadDir(4097)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}

	if len(entries) > 4096 {
		return nil, errors.New("too many entries in approval transport directory")
	}

	candidates := make([]candidate, 0)
	prefix := mac + "-"

	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasPrefix(name, prefix) || !strings.HasSuffix(name, ".sock") {
			continue
		}

		if !approvalwire.ValidID(strings.TrimSuffix(strings.TrimPrefix(name, prefix), ".sock")) {
			continue
		}

		info, statErr := entry.Info()
		if statErr != nil || !ownedSocket(info) {
			continue
		}

		candidates = append(candidates, candidate{path: filepath.Join(dir, name), modified: info.ModTime(), info: info})
	}
	// sshd creates each unique socket once. Modification time, then basename,
	// define ordering across calls and broker restarts; there is no registration lease.
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].modified.Equal(candidates[j].modified) {
			return candidates[i].path > candidates[j].path
		}

		return candidates[i].modified.After(candidates[j].modified)
	})

	return candidates, nil
}

func selectTransport(ctx context.Context, dir, mac string) (net.Conn, error) {
	for {
		candidates, err := transports(dir, mac)
		if err != nil {
			return nil, err
		}

		for _, c := range candidates {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}

			if err = Probe(ctx, c.path, mac); err != nil {
				// Only a refused connection establishes a stale socket. Timeouts, invalid
				// peers and other uncertain failures leave the pathname untouched.
				if errors.Is(err, syscall.ECONNREFUSED) {
					if removeErr := removeUnchanged(c.path, c.info); removeErr != nil {
						return nil, removeErr
					}
				}

				continue
			}

			conn, dialErr := (&net.Dialer{Timeout: 200 * time.Millisecond}).DialContext(ctx, "unix", c.path)
			if dialErr == nil {
				return conn, nil
			}
		}

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(25 * time.Millisecond):
		}
	}
}

func proxy(ctx context.Context, client, upstream net.Conn) {
	defer cleanup.Close(upstream)

	stop := context.AfterFunc(ctx, func() { cleanup.Close(upstream) })
	defer stop()

	finished := make(chan error, 2)

	copyOne := func(to io.Writer, from io.Reader) { _, err := io.Copy(to, from); finished <- err }
	go copyOne(upstream, client)
	go copyOne(client, upstream)
	// Any completion ends this one-request stream. Copy errors cannot produce a
	// decision or justify another route; closing preserves the SDK's uncertainty.
	<-finished
	cleanup.Close(client)
	cleanup.Close(upstream)
	<-finished
}

func unavailable(conn net.Conn) {
	if err := conn.SetDeadline(time.Now().Add(time.Second)); err != nil {
		return
	}

	var request approvalwire.Request
	if err := approvalwire.Read(conn, &request); err != nil {
		return
	}

	if err := json.NewEncoder(conn).Encode(approvalwire.Response{Version: approvalwire.Version, ID: request.ID, Decision: "unavailable"}); err != nil {
		return
	}
}

// Sweep is independent of request routing: a healthy newest socket must not
// prevent collection of older refused endpoints. Incremental directory reads
// keep cleanup available even when the routing scan reaches its safety cap.
func sweep(ctx context.Context, dir, mac string) {
	for {
		if ctx.Err() != nil {
			return
		}

		scan(ctx, dir, mac)

		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Minute):
		}
	}
}

func scan(ctx context.Context, dir, mac string) {
	file, err := os.Open(dir) // #nosec G304 -- The user broker owns this private canonical directory.
	if err != nil {
		return
	}
	defer cleanup.Close(file)

	for {
		entries, readErr := file.ReadDir(64)
		if readErr != nil && !errors.Is(readErr, io.EOF) {
			return
		}

		for _, entry := range entries {
			if ctx.Err() != nil {
				return
			}

			name := entry.Name()

			prefix := mac + "-"
			if !strings.HasPrefix(name, prefix) || !strings.HasSuffix(name, ".sock") || !approvalwire.ValidID(strings.TrimSuffix(strings.TrimPrefix(name, prefix), ".sock")) {
				continue
			}

			info, statErr := entry.Info()
			if statErr != nil || !ownedSocket(info) {
				continue
			}

			path := filepath.Join(dir, name)
			if probeErr := Probe(ctx, path, mac); errors.Is(probeErr, syscall.ECONNREFUSED) {
				if removeErr := removeUnchanged(path, info); removeErr != nil {
					return
				}
			}
		}

		if errors.Is(readErr, io.EOF) {
			return
		}

		select {
		case <-ctx.Done():
			return
		case <-time.After(10 * time.Millisecond):
		}
	}
}
