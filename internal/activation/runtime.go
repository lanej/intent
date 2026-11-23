// Package activation owns process identity and controlled approval cancellation.
package activation

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/lanej/intent/internal/cleanup"
)

type Process struct {
	PID           int    `json:"pid"`
	StartIdentity string `json:"start_identity"`
	NativeID      string `json:"native_id"`
	OwnerVerified bool   `json:"owner_verified"`
}

type Request struct {
	Action  string  `json:"action"`
	RunID   string  `json:"run_id,omitempty"`
	Process Process `json:"process"`
}

type Interrupted struct {
	RequestID string `json:"request_id"`
	Outcome   string `json:"outcome"`
}

type Checkpoint struct {
	StopSubmitted bool          `json:"stop_submitted,omitempty"`
	State         string        `json:"state"`
	RunID         string        `json:"run_id"`
	Interrupted   []Interrupted `json:"interrupted"`
}

type Session struct {
	SessionID   string `json:"session_id"`
	Restoration string `json:"restoration"`
}

type Target struct {
	MacID            string      `json:"mac_id"`
	Target           string      `json:"target"`
	ExpectedIdentity *string     `json:"expected_identity"`
	RunningIdentity  *string     `json:"running_identity"`
	Executable       string      `json:"executable"`
	Platform         string      `json:"platform"`
	Architecture     string      `json:"architecture"`
	Ready            bool        `json:"ready"`
	Process          Process     `json:"process"`
	Sessions         []Session   `json:"sessions"`
	Checkpoint       *Checkpoint `json:"checkpoint,omitempty"`
	Reason           string      `json:"reason,omitempty"`
}

type Result struct {
	SchemaVersion int      `json:"schema_version"`
	Targets       []Target `json:"targets"`
}

type activeRequest struct {
	id     string
	cancel context.CancelFunc
}

type Runtime struct {
	mu           sync.Mutex
	target       Target
	active       map[uint64]activeRequest
	sequence     uint64
	changed      chan struct{}
	checkpoint   *Checkpoint
	lastRun      string
	stop         context.CancelFunc
	shutdownOnce sync.Once
}

func Digest(path string) (string, error) {
	file, err := os.Open(path) // #nosec G304 -- The owner chooses its installed executable, never a path from an approval request.
	if err != nil {
		return "", err
	}
	defer cleanup.Close(file)

	hash := sha256.New()
	if _, err = io.Copy(hash, file); err != nil {
		return "", err
	}

	return hex.EncodeToString(hash.Sum(nil)), nil
}

// New captures the executing artifact once; later pointer changes cannot
// rewrite the running identity. The target is the stable owner endpoint.
func New(target, platform, architecture string, stop context.CancelFunc) (*Runtime, error) {
	executable, err := os.Executable()
	if err != nil {
		return nil, err
	}

	artifact := ImageIdentity()

	start, err := processIdentity(os.Getpid())
	if err != nil {
		return nil, err
	}

	var id [16]byte
	if _, err = rand.Read(id[:]); err != nil {
		return nil, err
	}

	process := Process{PID: os.Getpid(), StartIdentity: start, NativeID: hex.EncodeToString(id[:]), OwnerVerified: true}

	return &Runtime{target: Target{
		Target: target, RunningIdentity: artifact, ExpectedIdentity: artifact,
		Executable: executable, Platform: platform, Architecture: architecture, Ready: true, Process: process,
		Sessions: []Session{},
	}, active: map[uint64]activeRequest{}, changed: make(chan struct{}), stop: stop}, nil
}

func (r *Runtime) notify() {
	close(r.changed)
	r.changed = make(chan struct{})
}

// Begin admits one approval call. Checkpointing fences new calls and cancels
// admitted calls; completion is observed only when each handler invokes done.
func (r *Runtime) Begin(parent context.Context, id string) (context.Context, func(), error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if !r.target.Ready {
		return nil, nil, errors.New("approval service is checkpointed")
	}

	r.sequence++
	key := r.sequence
	ctx, cancel := context.WithCancel(parent)
	r.active[key] = activeRequest{id: id, cancel: cancel}

	var once sync.Once

	done := func() {
		once.Do(func() {
			cancel()
			r.mu.Lock()
			delete(r.active, key)
			r.notify()
			r.mu.Unlock()
		})
	}

	return ctx, done, nil
}

func validRun(value string) bool {
	if len(value) != 36 {
		return false
	}

	for index, char := range value {
		if index == 8 || index == 13 || index == 18 || index == 23 {
			if char != '-' {
				return false
			}
		} else if char < '0' || char > 'f' || (char > '9' && char < 'a') {
			return false
		}
	}

	return true
}

func (r *Runtime) Snapshot() Result {
	r.mu.Lock()
	defer r.mu.Unlock()

	target := r.target
	if r.checkpoint != nil {
		checkpoint := *r.checkpoint

		checkpoint.Interrupted = append([]Interrupted{}, checkpoint.Interrupted...)
		if len(r.active) == 0 {
			checkpoint.State = "confirmed"
		}

		target.Checkpoint = &checkpoint
	}

	return Result{SchemaVersion: 1, Targets: []Target{target}}
}

// Control never retries an approval. stop is returned only for a confirmed,
// incarnation-bound checkpoint, so the caller can send its reply before exit.
func (r *Runtime) Control(ctx context.Context, request Request) (Result, bool, error) {
	if request.Action == "inventory" || request.Action == "verify" {
		return r.Snapshot(), false, nil
	}

	r.mu.Lock()
	if request.Process != r.target.Process || !validRun(request.RunID) {
		r.mu.Unlock()
		return Result{}, false, errors.New("process incarnation or update identity differs")
	}

	switch request.Action {
	case "checkpoint":
		if r.lastRun == request.RunID {
			r.mu.Unlock()
			return Result{}, false, errors.New("checkpoint already restored; do not repeat cancellation")
		}

		if r.checkpoint != nil && r.checkpoint.RunID != request.RunID {
			r.mu.Unlock()
			return Result{}, false, errors.New("another operation owns the checkpoint")
		}

		if r.checkpoint == nil {
			r.target.Ready = false

			r.checkpoint = &Checkpoint{State: "pending", RunID: request.RunID, Interrupted: []Interrupted{}}
			for _, active := range r.active {
				r.checkpoint.Interrupted = append(r.checkpoint.Interrupted, Interrupted{RequestID: active.id, Outcome: "interrupted-or-unknown"})
				active.cancel()
			}
		}

		for len(r.active) != 0 {
			changed := r.changed
			r.mu.Unlock()

			select {
			case <-ctx.Done():
				return r.Snapshot(), false, nil
			case <-changed:
			}

			r.mu.Lock()
		}

		r.mu.Unlock()

		return r.Snapshot(), false, nil
	case "restore", "stop":
		if r.checkpoint == nil || r.checkpoint.RunID != request.RunID || len(r.active) != 0 {
			r.mu.Unlock()
			return Result{}, false, errors.New("matching confirmed checkpoint required")
		}

		if request.Action == "restore" {
			if r.checkpoint.StopSubmitted {
				r.mu.Unlock()
				return Result{}, false, errors.New("stop-submitted checkpoint is irreversible")
			}

			r.lastRun = request.RunID
			r.checkpoint = nil
			r.target.Ready = true
		}

		shutdown := request.Action == "stop" && r.checkpoint != nil && !r.checkpoint.StopSubmitted
		if shutdown {
			r.checkpoint.StopSubmitted = true
		}
		r.mu.Unlock()

		return r.Snapshot(), shutdown, nil
	default:
		r.mu.Unlock()
		return Result{}, false, fmt.Errorf("unsupported lifecycle action %q", request.Action)
	}
}

func (r *Runtime) Stop() {
	r.shutdownOnce.Do(func() {
		if r.stop != nil {
			r.stop()
		}
	})
}

func ControlSocket(endpoint string) string {
	sum := sha256.Sum256([]byte(filepath.Base(endpoint)))
	return filepath.Join(filepath.Dir(endpoint), "lifecycle-"+hex.EncodeToString(sum[:6])+".sock")
}

// ServeControl receives only lifecycle commands over a separate private owner
// socket; ordinary approval bytes continue through the existing transport.
func (r *Runtime) ServeControl(parent context.Context, listener net.Listener) error {
	ctx, cancel := context.WithCancel(parent)
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
		go func() {
			defer handlers.Done()
			defer cleanup.Close(conn)

			requestCtx, expire := context.WithTimeout(ctx, 59*time.Second)
			defer expire()

			closeOnExit := context.AfterFunc(requestCtx, func() { cleanup.Close(conn) })
			defer closeOnExit()

			if deadlineErr := conn.SetDeadline(time.Now().Add(time.Minute)); deadlineErr != nil {
				return
			}

			var request Request

			decoder := json.NewDecoder(io.LimitReader(conn, 4096))
			decoder.DisallowUnknownFields()

			if decodeErr := decoder.Decode(&request); decodeErr != nil {
				return
			}

			result, shutdown, commandErr := r.Control(requestCtx, request)
			if commandErr != nil {
				if encodeErr := json.NewEncoder(conn).Encode(map[string]string{"error": commandErr.Error()}); encodeErr != nil {
					return
				}

				return
			}

			if encodeErr := json.NewEncoder(conn).Encode(result); encodeErr != nil {
				return
			}

			if shutdown {
				r.Stop()
			}
		}()
	}
}

func (r *Runtime) SetMacID(id string) {
	r.mu.Lock()
	r.target.MacID = id
	r.mu.Unlock()
}
