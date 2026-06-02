package views

import (
	"fmt"
	"strings"

	"github.com/ghosttrace/ghosttrace/internal/alert"
)

func RenderAlerts(alerts []alert.Alert, selected, height int, sev func(alert.Severity, string) string) string {
	var b strings.Builder
	if len(alerts) == 0 {
		b.WriteString("\n  (No threats detected. Host monitor silent.)\n")
		return b.String()
	}
	
	limit := height
	if limit < 0 {
		limit = 0
	}
	
	// Print in reverse order (newest alerts first)
	for i := len(alerts) - 1; i >= 0 && limit > 0; i-- {
		a := alerts[i]
		cursor := " "
		if len(alerts)-1-i == selected {
			cursor = "▶"
		}
		
		severityTag := sev(a.Severity, fmt.Sprintf("[%s]", a.Severity))
		detail := a.Detail
		if len(detail) > 42 {
			detail = detail[:39] + "..."
		}
		
		// Render alert header card
		b.WriteString(fmt.Sprintf("%s %s PID %-5d %-12s\n  └─ %s\n", 
			cursor, severityTag, a.PID, a.Type, detail))
			
		// If selected, display actionable mitigation instructions in the CLI feed
		if len(alerts)-1-i == selected && len(a.Mitigations) > 0 {
			b.WriteString(fmt.Sprintf("     Mitigation: %s\n", strings.Join(a.Mitigations, " | ")))
			limit--
		}
		
		b.WriteString("\n")
		limit -= 3
	}
	return strings.TrimRight(b.String(), "\n")
}
