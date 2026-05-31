package ringbuf

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/ghosttrace/ghosttrace/internal/events"
)

var ErrClosed = errors.New("ring buffer consumer closed")

type nativeReader func(*events.RawEvent) bool

type Consumer struct {
	read   nativeReader
	pool   sync.Pool
	closed chan struct{}
}

func NewConsumer() *Consumer {
	return NewConsumerWithReader(nativeRead)
}

func NewConsumerWithReader(read nativeReader) *Consumer {
	if read == nil {
		read = func(*events.RawEvent) bool { return false }
	}
	return &Consumer{
		read: read,
		pool: sync.Pool{New: func() any {
			return &events.RawEvent{}
		}},
		closed: make(chan struct{}),
	}
}

func (c *Consumer) Close() {
	select {
	case <-c.closed:
	default:
		close(c.closed)
	}
}

func (c *Consumer) Read() (events.RawEvent, bool) {
	raw := c.pool.Get().(*events.RawEvent)
	defer func() {
		*raw = events.RawEvent{}
		c.pool.Put(raw)
	}()

	if !c.read(raw) {
		return events.RawEvent{}, false
	}
	return *raw, true
}

func (c *Consumer) ReadBlocking(ctx context.Context) (events.RawEvent, error) {
	backoff := 50 * time.Microsecond
	const maxBackoff = 10 * time.Millisecond

	for {
		if raw, ok := c.Read(); ok {
			return raw, nil
		}

		timer := time.NewTimer(backoff)
		select {
		case <-ctx.Done():
			timer.Stop()
			return events.RawEvent{}, ctx.Err()
		case <-c.closed:
			timer.Stop()
			return events.RawEvent{}, ErrClosed
		case <-timer.C:
		}

		if backoff < maxBackoff {
			backoff *= 2
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
		}
	}
}
