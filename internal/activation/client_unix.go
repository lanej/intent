//go:build !windows

package activation

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/lanej/intent/internal/approvaldiscovery"
	"github.com/lanej/intent/internal/cleanup"
)

// Call inspects an owned control socket. Connection loss leaves a mutation's
// outcome unknown; callers must inspect retained state rather than retry it.
func Call(parent context.Context, endpoint string, request Request) (Result, error) {
	path := ControlSocket(endpoint)
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || len(path) > 103 {
		return Result{}, errors.New("invalid lifecycle control socket")
	}

	if err := approvaldiscovery.PrivateDir(filepath.Dir(path), false); err != nil {
		return Result{}, err
	}

	info, err := os.Lstat(path)
	if err != nil {
		return Result{}, err
	}

	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int64(stat.Uid) != int64(os.Getuid()) || info.Mode()&os.ModeSocket == 0 || info.Mode().Perm() != 0o600 {
		return Result{}, errors.New("lifecycle socket is not private and owned")
	}

	ctx, cancel := context.WithTimeout(parent, time.Minute)
	defer cancel()

	conn, err := (&net.Dialer{}).DialContext(ctx, "unix", path)
	if err != nil {
		return Result{}, err
	}
	defer cleanup.Close(conn)

	stop := context.AfterFunc(ctx, func() { cleanup.Close(conn) })
	defer stop()

	deadline, _ := ctx.Deadline()
	if err = conn.SetDeadline(deadline); err != nil {
		return Result{}, err
	}

	if err = json.NewEncoder(conn).Encode(request); err != nil {
		return Result{}, errors.New("lifecycle request outcome unknown")
	}

	var response struct {
		Result
		Error string `json:"error"`
	}

	decoder := json.NewDecoder(io.LimitReader(conn, 1<<20))
	if err = decoder.Decode(&response); err != nil {
		return Result{}, errors.New("native lifecycle response unavailable or outcome unknown")
	}

	if response.Error != "" {
		return Result{}, errors.New(response.Error)
	}

	if response.SchemaVersion != 1 || len(response.Targets) != 1 {
		return Result{}, errors.New("native lifecycle response unavailable")
	}

	return response.Result, nil
}
