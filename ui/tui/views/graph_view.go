package views

import (
	"fmt"
	"sort"
	"strings"

	"github.com/ghosttrace/ghosttrace/internal/graph"
)

func RenderGraph(rows []graph.ProcessSnapshot, height int) string {
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].PPID == rows[j].PPID {
			return rows[i].PID < rows[j].PID
		}
		return rows[i].PPID < rows[j].PPID
	})
	var b strings.Builder
	limit := height
	for _, row := range rows {
		if limit <= 0 {
			break
		}
		name := row.Comm
		if name == "" {
			name = "-"
		}
		b.WriteString(fmt.Sprintf("%d -> %d  %s\n", row.PPID, row.PID, name))
		limit--
	}
	return strings.TrimRight(b.String(), "\n")
}
