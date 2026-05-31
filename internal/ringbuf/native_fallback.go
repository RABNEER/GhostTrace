//go:build !linux || !cgo

package ringbuf

import "github.com/ghosttrace/ghosttrace/internal/events"

func nativeRead(out *events.RawEvent) bool {
	_ = out
	return false
}
