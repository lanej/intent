//go:build !windows

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/lanej/intent/internal/approvaldiscovery"
	"github.com/lanej/intent/internal/approvalssh"
	"github.com/lanej/intent/internal/approvalwire"
	"github.com/lanej/intent/internal/cleanup"
)

type registration struct {
	Version int    `json:"version"`
	Mac     string `json:"mac"`
	Session string `json:"session"`
	Socket  string `json:"socket"`
}

type acknowledgment struct {
	Session string `json:"selected"`
	Error   string `json:"error,omitempty"`
}

type route struct{ registration }

type broker struct {
	mac       string
	mu        sync.Mutex
	selected  *route
	sessions  map[string]*route
	endpoints map[string]*route
}

func serveBroker(parent context.Context, dir, mac string) error {
	if !filepath.IsAbs(dir) || filepath.Clean(dir) != dir {
		return errors.New("broker directory must be absolute and clean")
	}

	if err := approvaldiscovery.PrivateDir(dir, true); err != nil {
		return err
	}

	lock, err := os.OpenFile(filepath.Join(dir, "broker.lock"), os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0o600) // #nosec G304 G703 -- Fixed lock name under the validated private broker directory; symlinks are refused.
	if err != nil {
		return err
	}
	defer cleanup.Close(lock)

	lockInfo, statErr := lock.Stat()
	if statErr != nil {
		return statErr
	}

	if !lockInfo.Mode().IsRegular() || lockInfo.Mode().Perm() != 0o600 {
		return errors.New("preserve unexpected broker lock")
	}

	if err = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return err
	}

	defer cleanup.Unlock(int(lock.Fd()))

	public, err := privateListen(parent, filepath.Join(dir, "approval.sock"))
	if err != nil {
		return err
	}
	defer cleanup.Close(public)

	control, err := privateListen(parent, filepath.Join(dir, "registration.sock"))
	if err != nil {
		return err
	}
	defer cleanup.Close(control)

	ctx, cancel := context.WithCancel(parent)
	defer cancel()

	stop := context.AfterFunc(ctx, func() { cleanup.Close(public); cleanup.Close(control) })
	defer stop()

	b := &broker{mac: mac, sessions: make(map[string]*route), endpoints: make(map[string]*route)}

	var handlers sync.WaitGroup

	finished := make(chan error, 2)
	go func() { finished <- accept(ctx, public, b.proxy, &handlers) }()
	go func() { finished <- accept(ctx, control, b.register, &handlers) }()

	first := <-finished

	cancel()

	second := <-finished

	handlers.Wait()

	return errors.Join(first, second)
}

func privateListen(ctx context.Context, path string) (net.Listener, error) {
	if info, err := os.Lstat(path); err == nil { // #nosec G703 -- Only fixed listener names under the private, locked broker directory reach this helper.
		stat, owned := info.Sys().(*syscall.Stat_t)
		if !owned || int64(stat.Uid) != int64(os.Getuid()) || info.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("preserve unexpected endpoint: %s", path)
		}

		conn, dialErr := (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "unix", path)
		if dialErr == nil {
			cleanup.Close(conn)
			return nil, errors.New("preserve live endpoint")
		}

		if !errors.Is(dialErr, syscall.ECONNREFUSED) && !errors.Is(dialErr, os.ErrNotExist) {
			return nil, dialErr
		}

		if err = os.Remove(path); err != nil { // #nosec G703 -- The private broker lock and stale owned socket checks authorize this exact endpoint removal.
			return nil, err
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}

	listener, err := (&net.ListenConfig{}).Listen(ctx, "unix", path)
	if err != nil {
		return nil, err
	}

	if err = os.Chmod(path, 0o600); err != nil { // #nosec G703 -- This is the just-created listener in the private broker directory.
		cleanup.Close(listener)
		return nil, err
	}

	return listener, nil
}

func accept(ctx context.Context, listener net.Listener, handle func(context.Context, net.Conn), handlers *sync.WaitGroup) error {
	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil //nolint:nilerr // Closing the listener is normal broker shutdown, not an accept failure.
			}

			return err
		}

		handlers.Add(1)
		go func() {
			defer handlers.Done()
			defer cleanup.Close(conn)

			stop := context.AfterFunc(ctx, func() { cleanup.Close(conn) })
			defer stop()

			handle(ctx, conn)
		}()
	}
}

func validEndpoint(r registration) error {
	dir := filepath.Dir(r.Socket)
	if r.Version != 1 || !approvalwire.ValidID(r.Mac) || !approvalwire.ValidID(r.Session) ||
		filepath.Clean(r.Socket) != r.Socket || filepath.Base(r.Socket) != "approval.sock" ||
		filepath.Dir(dir) != "/tmp" || !strings.HasPrefix(filepath.Base(dir), "intent-approval-") {
		return errors.New("invalid transport registration")
	}

	if err := approvaldiscovery.PrivateDir(dir, false); err != nil {
		return err
	}

	marker := filepath.Join(dir, "session")

	info, err := os.Lstat(marker)
	if err != nil {
		return err
	}

	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		return errors.New("invalid transport marker")
	}

	data, err := os.ReadFile(marker) // #nosec G304 -- A fixed marker name in the validated owned transport directory; symlinks were rejected.
	if err != nil {
		return err
	}

	if string(data) != r.Session {
		return errors.New("transport marker mismatch")
	}

	info, err = os.Lstat(r.Socket)
	if err != nil {
		return err
	}

	if info.Mode()&os.ModeSocket == 0 {
		return errors.New("transport is not a socket")
	}

	return nil
}

func (b *broker) register(ctx context.Context, conn net.Conn) {
	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return
	}

	var r registration
	if err := approvalwire.Read(conn, &r); err != nil {
		return
	}

	ack := acknowledgment{Session: r.Session}

	selected, err := b.selectRoute(ctx, r)
	if err != nil {
		ack.Error = err.Error()
		if encodeErr := json.NewEncoder(conn).Encode(ack); encodeErr != nil {
			log.Print(encodeErr)
		}

		return
	}
	defer b.removeRoute(selected)

	if err := json.NewEncoder(conn).Encode(ack); err != nil {
		return
	}

	if err := conn.SetDeadline(time.Time{}); err != nil {
		return
	}

	var extra [1]byte
	if _, err := io.ReadFull(conn, extra[:]); err != nil {
		return
	}
}

// Registration and endpoint ownership move together. Displaced routes retain
// their ownership until their own registration ends; they are never fallback.
func (b *broker) selectRoute(ctx context.Context, r registration) (*route, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.sessions[r.Session] != nil || b.endpoints[r.Socket] != nil {
		return nil, errors.New("transport session or endpoint is already owned")
	}

	if err := validEndpoint(r); err != nil {
		return nil, err
	}

	if r.Mac != b.mac {
		if err := approvalssh.Cleanup(r.Session, r.Socket); err != nil {
			log.Print(err)
		}

		return nil, errors.New("different Mac; explicit pairing change required")
	}

	probe, err := (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "unix", r.Socket)
	if err != nil {
		if cleanupErr := approvalssh.Cleanup(r.Session, r.Socket); cleanupErr != nil {
			log.Print(cleanupErr)
		}

		return nil, errors.New("forwarding is not ready")
	}

	cleanup.Close(probe)

	selected := &route{registration: r}
	b.sessions[r.Session] = selected
	b.endpoints[r.Socket] = selected
	b.selected = selected

	return selected, nil
}

func (b *broker) removeRoute(selected *route) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.selected == selected {
		b.selected = nil
	}

	delete(b.sessions, selected.Session)
	delete(b.endpoints, selected.Socket)
	// Keep ownership locked through deletion so a new registration cannot claim
	// the same path after map removal but before filesystem cleanup completes.
	if err := approvalssh.Cleanup(selected.Session, selected.Socket); err != nil {
		log.Print(err)
	}
}

func (b *broker) proxy(ctx context.Context, client net.Conn) {
	b.mu.Lock()
	selected := b.selected
	b.mu.Unlock()

	if selected == nil {
		unavailable(client)
		return
	}

	upstream, err := (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "unix", selected.Socket)
	if err != nil {
		unavailable(client)
		return
	}
	defer cleanup.Close(upstream)

	stop := context.AfterFunc(ctx, func() { cleanup.Close(upstream) })
	defer stop()

	finished := make(chan struct{}, 2)

	copyOne := func(to io.Writer, from io.Reader) {
		if _, copyErr := io.Copy(to, from); copyErr != nil && !errors.Is(copyErr, net.ErrClosed) {
			log.Print(copyErr)
		}

		finished <- struct{}{}
	}
	go copyOne(upstream, client)
	go copyOne(client, upstream)

	<-finished
	cleanup.Close(client)
	cleanup.Close(upstream)
	<-finished
}

func unavailable(conn net.Conn) {
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return
	}

	var request approvalwire.Request
	if err := approvalwire.Read(conn, &request); err != nil {
		return
	}

	response := approvalwire.Response{Version: approvalwire.Version, ID: request.ID, Decision: "unavailable"}
	if err := json.NewEncoder(conn).Encode(response); err != nil {
		log.Print(err)
	}
}

func register(ctx context.Context, dir string, r registration) error {
	brokerOwnsCleanup := false
	defer func() {
		if !brokerOwnsCleanup {
			if err := approvalssh.Cleanup(r.Session, r.Socket); err != nil {
				log.Print(err)
			}
		}
	}()

	conn, err := (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "unix", filepath.Join(dir, "registration.sock"))
	if err != nil {
		return err
	}
	defer cleanup.Close(conn)

	// Once submitted, only the broker may clean a validated endpoint. A lost
	// acknowledgment is uncertain setup, never permission to delete another lease.
	brokerOwnsCleanup = true

	stop := context.AfterFunc(ctx, func() { cleanup.Close(conn) })
	defer stop()

	if err = conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return err
	}

	if err = json.NewEncoder(conn).Encode(r); err != nil {
		return err
	}

	var ack acknowledgment
	if err = approvalwire.Read(conn, &ack); err != nil {
		return err
	}

	if ack.Error != "" {
		return errors.New(ack.Error)
	}

	if ack.Session != r.Session {
		return errors.New("registration identity mismatch")
	}

	if err = json.NewEncoder(os.Stdout).Encode(ack); err != nil {
		return err
	}

	if err = conn.SetDeadline(time.Time{}); err != nil {
		return err
	}

	ended := make(chan struct{}, 2)

	go func() {
		var one [1]byte
		if _, readErr := conn.Read(one[:]); readErr != nil && ctx.Err() == nil && !errors.Is(readErr, net.ErrClosed) {
			log.Print(readErr)
		}

		ended <- struct{}{}
	}()
	go func() {
		if _, readErr := io.Copy(io.Discard, os.Stdin); readErr != nil {
			log.Print(readErr)
		}

		ended <- struct{}{}
	}()

	<-ended

	return nil
}
