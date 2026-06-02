package views

import (
	"fmt"
	"sort"
	"strings"

	"github.com/ghosttrace/ghosttrace/internal/graph"
)

func RenderProcesses(rows []graph.ProcessSnapshot, selected, height int, score func(float64, string) string) string {
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Score == rows[j].Score {
			return rows[i].PID < rows[j].PID
		}
		return rows[i].Score > rows[j].Score
	})
	
	var b strings.Builder
	b.WriteString("PID      Process Name    Threat Level [Radar Index]\n")
	
	limit := height - 2
	if limit < 0 {
		limit = 0
	}
	for i, row := range rows {
		if i >= limit {
			break
		}
		cursor := " "
		if i == selected {
			cursor = ">"
		}
		name := row.Comm
		if name == "" {
			name = "-"
		}
		if len(name) > 15 {
			name = name[:15]
		}
		
		// Create a visual horizontal progress bar for threat/anomaly score
		barWidth := 10
		progressBar := makeProgressBar(row.Score, barWidth)
		barColorized := score(row.Score, fmt.Sprintf("[%s] %5.1f%%", progressBar, row.Score))
		
		b.WriteString(fmt.Sprintf("%s%-8d %-15s %s\n", cursor, row.PID, name, barColorized))
	}
	return strings.TrimRight(b.String(), "\n")
}

func makeProgressBar(score float64, width int) string {
	if width <= 0 {
		return ""
	}
	pct := score / 100.0
	filled := int(pct * float64(width))
	if filled > width {
		filled = width
	}
	if filled < 0 {
		filled = 0
	}
	unfilled := width - filled
	return strings.Repeat("█", filled) + strings.Repeat("░", unfilled)
}
