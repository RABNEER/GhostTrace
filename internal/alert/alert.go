package alert

import (
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
)

type Severity string

const (
	SeverityInfo     Severity = "INFO"
	SeverityWarn     Severity = "WARN"
	SeverityCritical Severity = "CRITICAL"
)

type AlertType string

const (
	AlertInjection  AlertType = "INJECTION"
	AlertRootkit    AlertType = "ROOTKIT"
	AlertDKOM       AlertType = "DKOM"
	AlertShellcode  AlertType = "SHELLCODE"
	AlertHollowProc AlertType = "HOLLOW_PROC"
)

type Alert struct {
	ID          string    `json:"id"`
	Severity    Severity  `json:"severity"`
	Type        AlertType `json:"type"`
	PID         uint32    `json:"pid"`
	Comm        string    `json:"comm"`
	Detail      string    `json:"detail"`
	Score       float64   `json:"score"`
	Timestamp   time.Time `json:"timestamp"`
	Mitigations []string  `json:"mitigations"`
}

func New(sev Severity, typ AlertType, pid uint32, comm, detail string, score float64) Alert {
	return Alert{
		ID:        uuid.NewString(),
		Severity:  sev,
		Type:      typ,
		PID:       pid,
		Comm:      comm,
		Detail:    detail,
		Score:     score,
		Timestamp: time.Now().UTC(),
		Mitigations: []string{
			fmt.Sprintf("inspect /proc/%d/maps", pid),
			fmt.Sprintf("consider isolating PID %d before termination", pid),
		},
	}
}

type Deduplicator struct {
	mu     sync.Mutex
	window time.Duration
	seen   map[string]time.Time
}

func NewDeduplicator(window time.Duration) *Deduplicator {
	if window <= 0 {
		window = 5 * time.Second
	}
	return &Deduplicator{
		window: window,
		seen:   make(map[string]time.Time),
	}
}

func (d *Deduplicator) Allow(a Alert) bool {
	d.mu.Lock()
	defer d.mu.Unlock()

	now := time.Now()
	for key, ts := range d.seen {
		if now.Sub(ts) > d.window*2 {
			delete(d.seen, key)
		}
	}

	key := fmt.Sprintf("%d:%s", a.PID, a.Type)
	if ts, ok := d.seen[key]; ok && now.Sub(ts) < d.window {
		return false
	}
	d.seen[key] = now
	return true
}

func SeverityForScore(score float64) Severity {
	switch {
	case score >= 70:
		return SeverityCritical
	case score >= 30:
		return SeverityWarn
	default:
		return SeverityInfo
	}
}
