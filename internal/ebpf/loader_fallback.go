//go:build !linux

package ebpf

import (
	"context"
	"errors"

	"github.com/ghosttrace/ghosttrace/internal/events"
)

var ErrTracingUnavailable = errors.New("kernel tracing filesystem is unavailable")

type Loader struct {
	procCh chan events.ProcessEvent
	memCh  chan events.MemEvent
}

func New(ctx context.Context) (*Loader, error) {
	_ = ctx
	return nil, ErrTracingUnavailable
}

func (l *Loader) ProcessEvents() <-chan events.ProcessEvent {
	return l.procCh
}

func (l *Loader) MemEvents() <-chan events.MemEvent {
	return l.memCh
}

func (l *Loader) Close() error {
	return nil
}
