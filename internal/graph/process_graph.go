package graph

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"github.com/ghosttrace/ghosttrace/internal/alert"
	"github.com/ghosttrace/ghosttrace/internal/events"
)

const protExec = 0x4

type Options struct {
	OrphanDetection       bool
	HollowProcess         bool
	SyscallSpikeMultiplier float64
	DKOMCheckInterval     time.Duration
}

func DefaultOptions() Options {
	return Options{
		OrphanDetection:       true,
		HollowProcess:         true,
		SyscallSpikeMultiplier: 5,
		DKOMCheckInterval:     500 * time.Millisecond,
	}
}

type ProcessGraph struct {
	mu       sync.RWMutex
	nodes    map[uint32]*ProcessNode
	options  Options
	lastDKOM time.Time
}

type ProcessNode struct {
	PID              uint32
	PPID             uint32
	Comm             string
	ExePath          string
	Children         []*ProcessNode
	SyscallHistogram [512]uint64
	MemEvents        []events.MemEvent
	AnomalyScore     float64
	FirstSeen        time.Time
	LastSeen         time.Time
	Exited           bool

	execAt      time.Time
	rateMean    float64
	rateM2      float64
	rateN       uint64
	lastSyscall time.Time
	lastGap     time.Duration
	burstCount  uint64
}

type ProcessSnapshot struct {
	PID          uint32
	PPID         uint32
	Comm         string
	Score        float64
	Status       string
	LastSeen     time.Time
	SyscallTotal uint64
}

func NewProcessGraph(opts Options) *ProcessGraph {
	if opts.SyscallSpikeMultiplier <= 1 {
		opts.SyscallSpikeMultiplier = 5
	}
	if opts.DKOMCheckInterval <= 0 {
		opts.DKOMCheckInterval = 500 * time.Millisecond
	}
	return &ProcessGraph{
		nodes:   make(map[uint32]*ProcessNode),
		options: opts,
	}
}

func (g *ProcessGraph) Update(ev events.ProcessEvent) []alert.Alert {
	g.mu.Lock()
	defer g.mu.Unlock()

	now := events.UnixNanos(ev.TimestampNs)
	node := g.ensureNodeLocked(ev.PID, ev.PPID, now)
	node.PPID = ev.PPID
	node.Comm = nonEmpty(ev.Comm, node.Comm)
	node.ExePath = nonEmpty(ev.ExePath, node.ExePath)
	node.LastSeen = now
	node.Exited = ev.Type == events.ProcessExit
	if ev.Type == events.ProcessExec {
		node.execAt = now
	}
	g.reparentLocked(node)
	g.reparentOrphansLocked(node)
	return g.detectAnomaliesLocked(now)
}

func (g *ProcessGraph) AddSyscall(ev events.SyscallEvent) []alert.Alert {
	g.mu.Lock()
	defer g.mu.Unlock()

	now := events.UnixNanos(ev.TimestampNs)
	node := g.ensureNodeLocked(ev.PID, ev.PPID, now)
	node.LastSeen = now
	node.Comm = nonEmpty(commString(ev.Comm), node.Comm)
	if ev.SyscallNr < uint32(len(node.SyscallHistogram)) {
		node.SyscallHistogram[ev.SyscallNr]++
	}
	g.updateRateLocked(node, now)
	return g.detectAnomaliesLocked(now)
}

func (g *ProcessGraph) AddMemEvent(ev events.MemEvent) []alert.Alert {
	g.mu.Lock()
	defer g.mu.Unlock()

	now := events.UnixNanos(ev.TimestampNs)
	node := g.ensureNodeLocked(ev.PID, 0, now)
	node.LastSeen = now
	node.MemEvents = appendBounded(node.MemEvents, ev, 64)
	return g.detectAnomaliesLocked(now)
}

func (g *ProcessGraph) Snapshot() []ProcessSnapshot {
	g.mu.RLock()
	defer g.mu.RUnlock()

	out := make([]ProcessSnapshot, 0, len(g.nodes))
	for _, n := range g.nodes {
		total := uint64(0)
		for _, c := range n.SyscallHistogram {
			total += c
		}
		status := "running"
		if n.Exited {
			status = "exited"
		}
		out = append(out, ProcessSnapshot{
			PID:          n.PID,
			PPID:         n.PPID,
			Comm:         n.Comm,
			Score:        n.AnomalyScore,
			Status:       status,
			LastSeen:     n.LastSeen,
			SyscallTotal: total,
		})
	}
	return out
}

func (g *ProcessGraph) ensureNodeLocked(pid, ppid uint32, now time.Time) *ProcessNode {
	if pid == 0 {
		pid = 1
	}
	if n, ok := g.nodes[pid]; ok {
		if n.FirstSeen.IsZero() {
			n.FirstSeen = now
		}
		return n
	}
	n := &ProcessNode{
		PID:       pid,
		PPID:      ppid,
		FirstSeen: now,
		LastSeen:  now,
	}
	g.nodes[pid] = n
	g.reparentLocked(n)
	return n
}

func (g *ProcessGraph) reparentLocked(node *ProcessNode) {
	if node.PPID == 0 || node.PPID == node.PID {
		return
	}
	parent, ok := g.nodes[node.PPID]
	if !ok {
		return
	}
	for _, child := range parent.Children {
		if child.PID == node.PID {
			return
		}
	}
	parent.Children = append(parent.Children, node)
}

func (g *ProcessGraph) reparentOrphansLocked(parent *ProcessNode) {
	for _, child := range g.nodes {
		if child.PPID == parent.PID && child.PID != parent.PID {
			g.reparentLocked(child)
		}
	}
}

func (g *ProcessGraph) updateRateLocked(node *ProcessNode, now time.Time) {
	if node.lastSyscall.IsZero() {
		node.lastSyscall = now
		return
	}
	gap := now.Sub(node.lastSyscall)
	node.lastGap = gap
	node.lastSyscall = now
	if gap <= 0 {
		return
	}
	rate := float64(time.Second) / float64(gap)
	node.rateN++
	delta := rate - node.rateMean
	node.rateMean += delta / float64(node.rateN)
	node.rateM2 += delta * (rate - node.rateMean)
	if gap < 20*time.Millisecond {
		node.burstCount++
	} else {
		node.burstCount = 0
	}
}

func (g *ProcessGraph) detectAnomaliesLocked(now time.Time) []alert.Alert {
	var out []alert.Alert
	runDKOM := g.lastDKOM.IsZero() || now.Sub(g.lastDKOM) >= g.options.DKOMCheckInterval
	if runDKOM {
		g.lastDKOM = now
	}

	for _, node := range g.nodes {
		var observations []observation
		if g.options.OrphanDetection {
			observations = appendObservation(observations, detectOrphan(g.nodes, node))
		}
		if g.options.HollowProcess {
			observations = appendObservation(observations, detectHollowProcess(node))
		}
		observations = appendObservation(observations, detectSyscallSpike(node, g.options.SyscallSpikeMultiplier))
		if runDKOM {
			observations = appendObservation(observations, detectDKOM(node))
		}
		observations = appendObservation(observations, detectTimingGap(node))

		score, detail, typ := combineObservations(observations)
		if score <= 0 {
			continue
		}
		node.AnomalyScore = score
		out = append(out, alert.New(alert.SeverityForScore(score), typ, node.PID, node.Comm, detail, score))
	}
	return out
}

func (g *ProcessGraph) DetectAnomalies() []alert.Alert {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.detectAnomaliesLocked(time.Now())
}

func appendObservation(in []observation, obs observation) []observation {
	if obs.triggered {
		return append(in, obs)
	}
	return in
}

func appendBounded[T any](in []T, ev T, limit int) []T {
	in = append(in, ev)
	if len(in) > limit {
		copy(in, in[len(in)-limit:])
		in = in[:limit]
	}
	return in
}

func commString(comm [16]byte) string {
	n := 0
	for n < len(comm) && comm[n] != 0 {
		n++
	}
	return string(comm[:n])
}

func nonEmpty(next, current string) string {
	if next != "" {
		return next
	}
	return current
}

func procExists(pid uint32) bool {
	if runtime.GOOS != "linux" {
		return true
	}
	_, err := os.Stat(filepath.Join("/proc", fmt.Sprint(pid)))
	return err == nil
}
