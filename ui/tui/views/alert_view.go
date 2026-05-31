package views

import (
	"fmt"
	"strings"

	"github.com/ghosttrace/ghosttrace/internal/alert"
)

func RenderAlerts(alerts []alert.Alert, selected, height int, sev func(alert.Severity, string) string) string {
	var b strings.Builder
	b.WriteString("Severity  PID      Type          Detail\n")
	limit := height - 2
	if limit < 0 {
		limit = 0
	}
	for i := len(alerts) - 1; i >= 0 && limit > 0; i-- {
		a := alerts[i]
		cursor := " "
		if len(alerts)-1-i == selected {
			cursor = ">"
		}
		detail := a.Detail
		if len(detail) > 36 {
			detail = detail[:36]
		}
		b.WriteString(fmt.Sprintf("%s%-8s %-7d %-12s %s\n", cursor, sev(a.Severity, string(a.Severity)), a.PID, a.Type, detail))
		limit--
	}
	return strings.TrimRight(b.String(), "\n")
}
