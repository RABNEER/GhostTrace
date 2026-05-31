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
	b.WriteString("PID      Name             Score  Status\n")
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
		if len(name) > 14 {
			name = name[:14]
		}
		scoreText := score(row.Score, fmt.Sprintf("%5.1f", row.Score))
		b.WriteString(fmt.Sprintf("%s%-7d %-14s %s  %s\n", cursor, row.PID, name, scoreText, row.Status))
	}
	return strings.TrimRight(b.String(), "\n")
}
