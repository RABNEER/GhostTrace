package ringbuf

import (
	"context"
	"testing"
	"time"

	"github.com/ghosttrace/ghosttrace/internal/events"
)

func TestReadBlocking(t *testing.T) {
	raw := events.EncodeSyscall(events.SyscallEvent{PID: 7, SyscallNr: 59})
	called := false
	c := NewConsumerWithReader(func(out *events.RawEvent) bool {
		if called {
			return false
		}
		called = true
		*out = raw
		return true
	})

	got, err := c.ReadBlocking(context.Background())
	if err != nil {
		t.Fatalf("ReadBlocking returned error: %v", err)
	}
	decoded, err := events.DecodeRaw(got)
	if err != nil {
		t.Fatalf("DecodeRaw returned error: %v", err)
	}
	if decoded.Syscall.PID != 7 || decoded.Syscall.SyscallNr != 59 {
		t.Fatalf("unexpected decoded event: %+v", decoded.Syscall)
	}
}

func TestReadBlockingContextCancel(t *testing.T) {
	c := NewConsumerWithReader(nil)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Millisecond)
	defer cancel()

	if _, err := c.ReadBlocking(ctx); err == nil {
		t.Fatal("expected context error")
	}
}
