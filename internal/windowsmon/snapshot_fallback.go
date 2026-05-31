//go:build !windows

package windowsmon

import (
	"context"
	"errors"
)

var ErrUnsupported = errors.New("windows process monitor is only available on Windows")

type Process struct {
	PID     uint32
	PPID    uint32
	Comm    string
	ExePath string
}

func Snapshot(ctx context.Context) ([]Process, error) {
	_ = ctx
	return nil, ErrUnsupported
}
