// Package intent owns one-time approval, independently of credential leases.
package intent

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"sync"
	"time"

	"github.com/lanej/intent/internal/cleanup"

	approval "github.com/lanej/intent"
	"github.com/lanej/intent/internal/approvalwire"
)

type Prompt struct {
	Version int                     `json:"version"`
	Kind    string                  `json:"kind"`
	ID      string                  `json:"request_id"`
	Host    string                  `json:"host"`
	Session string                  `json:"session"`
	Shared  bool                    `json:"shared,omitempty"`
	Reason  string                  `json:"reason"`
	Agent   *approval.AgentIdentity `json:"agent,omitempty"`
}

// Authenticate is the isolation boundary for native UI and OS authentication.
type Authenticate func(context.Context, Prompt) approval.Decision

type Service struct {
	Host         string
	Shared       bool
	Session      string
	Authenticate Authenticate
	mu           sync.Mutex
	active       bool
}

func (s *Service) Serve(ctx context.Context, listener net.Listener) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	stop := context.AfterFunc(ctx, func() { cleanup.Close(listener) })
	defer stop()

	var handlers sync.WaitGroup

	defer func() { cancel(); handlers.Wait() }()

	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}

			return err
		}

		handlers.Add(1)
		go func() { defer handlers.Done(); s.handle(ctx, conn) }()
	}
}

func (s *Service) handle(parent context.Context, conn net.Conn) {
	defer cleanup.Close(conn)

	ctx, cancel := context.WithCancel(parent)
	defer cancel()

	stop := context.AfterFunc(ctx, func() { cleanup.Close(conn) })
	defer stop()

	if err := conn.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return
	}

	var request approvalwire.Request
	if approvalwire.Read(conn, &request) != nil {
		return
	}

	response := approvalwire.Response{Version: approvalwire.Version, ID: request.ID}
	reply := func() {
		if err := conn.SetWriteDeadline(time.Now().Add(time.Second)); err != nil {
			return
		}

		if err := json.NewEncoder(conn).Encode(response); err != nil {
			return
		}
	}

	if request.Version != approvalwire.Version || !approvalwire.ValidID(request.ID) || !approvalwire.ValidReason(request.Reason) || request.TimeoutMS <= 0 || !approvalwire.ValidAgent(request.Agent) {
		response.Error = "invalid approval request or unsupported version"

		reply()

		return
	}
	// Clamp before converting untrusted milliseconds to a duration.
	timeout := time.Duration(min(request.TimeoutMS, approval.DefaultTimeout.Milliseconds())) * time.Millisecond

	ctx, expire := context.WithTimeout(ctx, timeout)
	defer expire()

	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		return
	}
	// No second request is valid. EOF, extra bytes or any read failure cancels UI.
	go func() {
		var b [1]byte
		// A byte, EOF, or any read error all revoke this one-request connection.
		if _, err := io.ReadFull(conn, b[:]); err != nil {
			cancel()
			return
		}

		cancel()
	}()

	s.mu.Lock()
	if s.active {
		s.mu.Unlock()

		response.Decision = string(approval.Busy)

		reply()

		return
	}

	s.active = true
	s.mu.Unlock()

	var released sync.Once

	release := func() { released.Do(func() { s.mu.Lock(); s.active = false; s.mu.Unlock() }) }
	defer release()

	var agent *approval.AgentIdentity
	if request.Agent != nil {
		agent = &approval.AgentIdentity{Type: request.Agent.Type, ID: request.Agent.ID}
	}

	decision := approval.Unavailable
	if s.Authenticate != nil && ctx.Err() == nil {
		decision = s.Authenticate(ctx, Prompt{Version: 1, Kind: "one_time", ID: request.ID, Host: s.Host, Session: s.Session, Shared: s.Shared, Reason: request.Reason, Agent: agent})
	}

	if ctx.Err() != nil {
		if parent.Err() != nil {
			return
		}

		if ctx.Err() == context.DeadlineExceeded {
			decision = approval.TimedOut
		} else {
			return
		}
	}

	response.Decision = string(decision)

	release()
	reply()
}
