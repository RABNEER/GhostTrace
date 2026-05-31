package graph

import (
	"fmt"
	"strings"
	"time"

	"github.com/ghosttrace/ghosttrace/internal/alert"
)

type observation struct {
	triggered bool
	score     float64
	detail    string
	alertType alert.AlertType
	weight    float64
}

func detectOrphan(nodes map[uint32]*ProcessNode, node *ProcessNode) observation {
	if node.PID == 1 || node.PPID == 0 || node.PPID == 1 || node.Exited {
		return observation{}
	}
	if _, ok := nodes[node.PPID]; ok {
		return observation{}
	}
	return observation{
		triggered: true,
		score:     45,
		detail:    fmt.Sprintf("parent PID %d is missing from process graph", node.PPID),
		alertType: alert.AlertRootkit,
		weight:    0.35,
	}
}

func detectHollowProcess(node *ProcessNode) observation {
	if node.execAt.IsZero() {
		return observation{}
	}
	for i := len(node.MemEvents) - 1; i >= 0; i-- {
		ev := node.MemEvents[i]
		if ev.Prot&protExec == 0 {
			continue
		}
		t := time.Unix(0, int64(ev.TimestampNs))
		if !t.Before(node.execAt) && t.Sub(node.execAt) <= 2*time.Second {
			return observation{
				triggered: true,
				score:     78,
				detail:    fmt.Sprintf("exec followed by executable anonymous mapping at 0x%x", ev.Addr),
				alertType: alert.AlertHollowProc,
				weight:    0.7,
			}
		}
	}
	return observation{}
}

func detectSyscallSpike(node *ProcessNode, multiplier float64) observation {
	if node.rateN < 10 || node.lastGap <= 0 {
		return observation{}
	}
	currentRate := float64(time.Second) / float64(node.lastGap)
	if node.rateMean <= 0 || currentRate < node.rateMean*multiplier {
		return observation{}
	}
	return observation{
		triggered: true,
		score:     clamp(currentRate/(node.rateMean*multiplier)*55, 35, 85),
		detail:    fmt.Sprintf("syscall rate %.1f/sec exceeds rolling baseline %.1f/sec", currentRate, node.rateMean),
		alertType: alert.AlertInjection,
		weight:    0.45,
	}
}

func detectDKOM(node *ProcessNode) observation {
	if node.PID == 0 || node.Exited || procExists(node.PID) {
		return observation{}
	}
	return observation{
		triggered: true,
		score:     90,
		detail:    "PID observed in telemetry but missing from /proc",
		alertType: alert.AlertDKOM,
		weight:    1,
	}
}

func detectTimingGap(node *ProcessNode) observation {
	if node.lastGap <= 100*time.Millisecond || node.burstCount < 5 {
		return observation{}
	}
	return observation{
		triggered: true,
		score:     60,
		detail:    fmt.Sprintf("syscall burst after %.0fms timing gap", float64(node.lastGap)/float64(time.Millisecond)),
		alertType: alert.AlertInjection,
		weight:    0.5,
	}
}

func combineObservations(obs []observation) (float64, string, alert.AlertType) {
	if len(obs) == 0 {
		return 0, "", ""
	}
	score := 0.0
	weight := 0.0
	details := make([]string, 0, len(obs))
	typ := obs[0].alertType
	for _, o := range obs {
		score += o.score * o.weight
		weight += o.weight
		details = append(details, o.detail)
		if o.score > 80 {
			typ = o.alertType
		}
	}
	if weight > 0 {
		score /= weight
	}
	return clamp(score, 0, 100), strings.Join(details, "; "), typ
}

func clamp(v, minV, maxV float64) float64 {
	if v < minV {
		return minV
	}
	if v > maxV {
		return maxV
	}
	return v
}
