package graph

import (
	"testing"
	"time"

	"github.com/ghosttrace/ghosttrace/internal/events"
)

func TestOrphanDetection(t *testing.T) {
	g := NewProcessGraph(DefaultOptions())
	alerts := g.Update(events.ProcessEvent{
		Type:        events.ProcessFork,
		PID:         100,
		PPID:        99,
		Comm:        "child",
		TimestampNs: uint64(time.Now().UnixNano()),
	})
	if len(alerts) == 0 {
		t.Fatal("expected orphan alert")
	}
}

func TestHollowProcessDetection(t *testing.T) {
	g := NewProcessGraph(DefaultOptions())
	now := time.Now()
	g.Update(events.ProcessEvent{
		Type:        events.ProcessExec,
		PID:         200,
		PPID:        1,
		Comm:        "target",
		TimestampNs: uint64(now.UnixNano()),
	})
	alerts := g.AddMemEvent(events.MemEvent{
		PID:         200,
		Addr:        0x1000,
		Len:         4096,
		Prot:        protExec,
		TimestampNs: uint64(now.Add(100 * time.Millisecond).UnixNano()),
	})
	if len(alerts) == 0 {
		t.Fatal("expected hollow process alert")
	}
}
