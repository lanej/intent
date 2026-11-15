// Package intent requests one-time human approval from an Intent Mac session.
// It does not authorize or execute actions: callers must proceed only after a
// confirmed Approved result. Reasons are caller claims, not verified commands.
package intent

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/lanej/intent/internal/cleanup"

	"github.com/lanej/intent/internal/approvaldiscovery"
	"github.com/lanej/intent/internal/approvalwire"
)

const (
	SocketEnv      = "INTENT_APPROVAL_SOCKET"
	DefaultTimeout = 2 * time.Minute
)

type (
	Request struct {
		Reason string
		// Agent is optional caller-supplied context. Supply it explicitly in agent
		// applications; nil represents an unspecified caller. Never mutate it
		// concurrently with Approve. Metadata requires an updated broker.
		Agent *AgentIdentity
	}
	Decision string
)

const (
	Approved    Decision = "approved"
	Denied      Decision = "denied"
	Cancelled   Decision = "cancelled"
	TimedOut    Decision = "timed_out"
	Unavailable Decision = "unavailable"
	Busy        Decision = "busy"
)

type Result struct {
	RequestID string   `json:"request_id"`
	Decision  Decision `json:"decision"`
}

// ErrOutcomeUnknown means the request may have reached the Mac, but no valid
// decision was received. Do not proceed or automatically repeat the request.
var ErrOutcomeUnknown = errors.New("approval outcome unknown")

// Client is immutable and safe for concurrent use. Each call uses a new connection.
type Client struct {
	socketPath    string
	discoveryPath string
}

func NewClient(socketPath string) *Client { return &Client{socketPath: socketPath} }
func ClientFromEnv() (*Client, error) {
	path := os.Getenv(SocketEnv)
	if path == "" {
		discoveryPath, err := approvaldiscovery.Path()
		if err != nil {
			return nil, fmt.Errorf("discover approval socket: %w", err)
		}

		return &Client{discoveryPath: discoveryPath}, nil
	}

	return NewClient(path), nil
}

// Approve waits for a confirmed decision. A nil error does not imply approval:
// inspect Result.Decision. Cancellation returns a context error and closes the
// request; transport failure after sending preserves uncertainty.
func (c *Client) Approve(ctx context.Context, request Request) (Result, error) {
	if !approvalwire.ValidReason(request.Reason) {
		return Result{}, errors.New("reason must be nonempty UTF-8, at most 4096 bytes, without control or formatting characters")
	}

	var agent *approvalwire.AgentIdentity

	if request.Agent != nil {
		snapshot := *request.Agent
		if err := snapshot.Validate(); err != nil {
			return Result{}, err
		}

		agent = snapshot.wire()
	}

	if c == nil || c.socketPath == "" && c.discoveryPath == "" {
		return Result{}, errors.New("approval socket is required")
	}

	ctx, cancel := context.WithTimeout(ctx, DefaultTimeout)
	defer cancel()

	if err := ctx.Err(); err != nil {
		return Result{}, err
	}

	path := c.socketPath
	if c.discoveryPath != "" {
		var err error

		path, err = c.discover(ctx)
		if err != nil {
			return Result{}, err
		}
	}

	conn, err := (&net.Dialer{}).DialContext(ctx, "unix", path)
	if err != nil {
		return Result{}, fmt.Errorf("connect approval socket: %w", err)
	}
	defer cleanup.Close(conn)

	deadline, _ := ctx.Deadline()
	if err = conn.SetDeadline(deadline); err != nil {
		return Result{}, fmt.Errorf("set approval deadline: %w", err)
	}

	stop := context.AfterFunc(ctx, func() { cleanup.Close(conn) })
	defer stop()

	nonce := make([]byte, 16)
	if _, err = rand.Read(nonce); err != nil {
		return Result{}, err
	}

	id := hex.EncodeToString(nonce)
	r := approvalwire.Request{Version: approvalwire.Version, ID: id, Reason: request.Reason, TimeoutMS: max(1, time.Until(deadline).Milliseconds()), Agent: agent}

	var response approvalwire.Response

	err = json.NewEncoder(conn).Encode(r)
	if err == nil {
		err = approvalwire.Read(conn, &response)
	}

	if err != nil {
		if ctx.Err() != nil {
			return Result{}, ctx.Err()
		}

		if !time.Now().Before(deadline) {
			return Result{}, context.DeadlineExceeded
		}

		return Result{}, fmt.Errorf("%w: %w", ErrOutcomeUnknown, err)
	}

	return decisionResult(ctx, id, response)
}

// Discovery retries only reading setup metadata. No approval request is sent
// until an endpoint is ready, and submitted requests are never retried.
func (c *Client) discover(parent context.Context) (string, error) {
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()

	for {
		receipt, err := approvaldiscovery.ReadPath(c.discoveryPath)
		if err == nil {
			return receipt.Socket, nil
		}

		if !os.IsNotExist(err) {
			return "", fmt.Errorf("discover approval socket: %w", err)
		}

		select {
		case <-ctx.Done():
			return "", fmt.Errorf("SSH approval setup unavailable: %w", ctx.Err())
		case <-time.After(50 * time.Millisecond):
		}
	}
}

// Interpret a received frame only while the request is still live. A buffered
// response can decode successfully even when cancellation races the read.
func decisionResult(ctx context.Context, id string, response approvalwire.Response) (Result, error) {
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}

	if deadline, ok := ctx.Deadline(); ok && !time.Now().Before(deadline) {
		return Result{}, context.DeadlineExceeded
	}

	if response.Version != approvalwire.Version || response.ID != id {
		return Result{}, fmt.Errorf("%w: invalid response identity or version", ErrOutcomeUnknown)
	}

	if response.Error != "" {
		if response.Decision != "" {
			return Result{}, fmt.Errorf("%w: conflicting response", ErrOutcomeUnknown)
		}

		return Result{}, fmt.Errorf("approval service: %s", response.Error)
	}

	decision := Decision(response.Decision)
	switch decision {
	case Approved, Denied, Cancelled, TimedOut, Unavailable, Busy:
		return Result{RequestID: id, Decision: decision}, nil
	default:
		return Result{}, fmt.Errorf("%w: invalid decision", ErrOutcomeUnknown)
	}
}
