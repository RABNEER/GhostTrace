package tui

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/ghosttrace/ghosttrace/internal/alert"
	"github.com/ghosttrace/ghosttrace/internal/graph"
	"github.com/ghosttrace/ghosttrace/ui/tui/views"
)

type Stats struct {
	EventsPerSec     int
	TotalProcesses   int
	ScanHitsToday    int
	Uptime           time.Duration
	SelfCPUJiffies   uint64
	SelfMemoryBytes  uint64
}

type Dashboard struct {
	graph     *graph.ProcessGraph
	alerts    []alert.Alert
	stats     Stats
	started   time.Time
	width     int
	height    int
	selectedP int
	selectedA int
	paused    bool
	expanded  bool
	err       error
}

type alertMsg alert.Alert
type statsMsg Stats
type tickMsg time.Time

func Run(ctx context.Context, g *graph.ProcessGraph, alertCh <-chan alert.Alert, statsCh <-chan Stats) error {
	model := &Dashboard{graph: g, started: time.Now()}
	p := tea.NewProgram(model, tea.WithAltScreen())

	go func() {
		for {
			select {
			case <-ctx.Done():
				p.Quit()
				return
			case a, ok := <-alertCh:
				if !ok {
					return
				}
				p.Send(alertMsg(a))
			case s, ok := <-statsCh:
				if !ok {
					return
				}
				p.Send(statsMsg(s))
			}
		}
	}()

	_, err := p.Run()
	return err
}

func (d *Dashboard) Init() tea.Cmd {
	return tickCmd()
}

func (d *Dashboard) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch m := msg.(type) {
	case tea.WindowSizeMsg:
		d.width = m.Width
		d.height = m.Height
	case tea.KeyMsg:
		return d.handleKey(m)
	case alertMsg:
		if !d.paused {
			d.alerts = append(d.alerts, alert.Alert(m))
		}
	case statsMsg:
		d.stats = Stats(m)
	case tickMsg:
		d.stats.Uptime = time.Since(d.started)
		d.stats.SelfCPUJiffies, d.stats.SelfMemoryBytes = readSelfStat()
		return d, tickCmd()
	}
	return d, nil
}

func (d *Dashboard) View() string {
	if d.width == 0 || d.height == 0 {
		return "initializing..."
	}
	bodyHeight := d.height - 2
	if bodyHeight < 3 {
		bodyHeight = 3
	}
	leftW := max(28, d.width*40/100)
	midW := max(28, d.width*35/100)
	rightW := max(24, d.width-leftW-midW)

	rows := d.graph.Snapshot()
	d.stats.TotalProcesses = len(rows)

	left := stylePane.Width(leftW-2).Height(bodyHeight).Render(
		styleTitle.Render("Processes") + "\n" +
			views.RenderProcesses(rows, d.selectedP, bodyHeight-2, func(score float64, s string) string {
				return scoreStyle(score).Render(s)
			}),
	)
	middle := stylePane.Width(midW-2).Height(bodyHeight).Render(
		styleTitle.Render("Alerts") + "\n" +
			views.RenderAlerts(d.alerts, d.selectedA, bodyHeight-2, severityRender),
	)
	right := stylePane.Width(rightW-2).Height(bodyHeight).Render(
		styleTitle.Render("Stats") + "\n" +
			d.renderStats(bodyHeight-2, rows),
	)

	bottom := styleBottom.Width(d.width).Render("[q]uit  [m]ode  [p]ause  [e]xport  [?]help")
	return lipgloss.JoinHorizontal(lipgloss.Top, left, middle, right) + "\n" + bottom
}

func (d *Dashboard) handleKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "q", "ctrl+c":
		return d, tea.Quit
	case "down", "j":
		d.selectedP++
	case "up":
		if d.selectedP > 0 {
			d.selectedP--
		}
	case "enter":
		d.expanded = !d.expanded
	case "p":
		d.paused = !d.paused
	case "e":
		if err := d.exportAlerts(); err != nil {
			d.err = err
		}
	case "k":
		d.killSelected()
	}
	return d, nil
}

func (d *Dashboard) renderStats(height int, rows []graph.ProcessSnapshot) string {
	lines := []string{
		fmt.Sprintf("Events/sec: %d", d.stats.EventsPerSec),
		fmt.Sprintf("Processes:  %d", len(rows)),
		fmt.Sprintf("Scan hits:  %d", d.stats.ScanHitsToday),
		fmt.Sprintf("CPU ticks:  %d", d.stats.SelfCPUJiffies),
		fmt.Sprintf("RSS bytes:  %d", d.stats.SelfMemoryBytes),
		fmt.Sprintf("Uptime:     %s", d.stats.Uptime.Truncate(time.Second)),
	}
	if d.paused {
		lines = append(lines, styleWarn.Render("Paused"))
	}
	if d.err != nil {
		lines = append(lines, styleCrit.Render(d.err.Error()))
	}
	lines = append(lines, "", "Lineage")
	graphText := views.RenderGraph(rows, max(0, height-len(lines)))
	if graphText != "" {
		lines = append(lines, graphText)
	}
	return strings.Join(lines, "\n")
}

func (d *Dashboard) exportAlerts() error {
	name := fmt.Sprintf("ghosttrace_%s.json", time.Now().Format("20060102_150405"))
	path := filepath.Join(".", name)
	data, err := json.MarshalIndent(d.alerts, "", "  ")
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	return writeFileContext(ctx, path, data, 0600)
}

func (d *Dashboard) killSelected() {
	rows := d.graph.Snapshot()
	if d.selectedP < 0 || d.selectedP >= len(rows) {
		return
	}
	proc, err := os.FindProcess(int(rows[d.selectedP].PID))
	if err != nil {
		d.err = err
		return
	}
	if err := proc.Kill(); err != nil {
		d.err = err
	}
}

func severityRender(sev alert.Severity, s string) string {
	switch sev {
	case alert.SeverityCritical:
		return styleCrit.Render(s)
	case alert.SeverityWarn:
		return styleWarn.Render(s)
	default:
		return styleInfo.Render(s)
	}
}

func tickCmd() tea.Cmd {
	return tea.Tick(time.Second, func(t time.Time) tea.Msg { return tickMsg(t) })
}

func writeFileContext(ctx context.Context, path string, data []byte, perm os.FileMode) error {
	ch := make(chan error, 1)
	go func() {
		ch <- os.WriteFile(path, data, perm)
	}()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-ch:
		return err
	}
}

func readSelfStat() (uint64, uint64) {
	data, err := os.ReadFile("/proc/self/stat")
	if err != nil {
		return 0, 0
	}
	fields := strings.Fields(string(data))
	if len(fields) < 24 {
		return 0, 0
	}
	var utime, stime, rss uint64
	_, _ = fmt.Sscanf(fields[13], "%d", &utime)
	_, _ = fmt.Sscanf(fields[14], "%d", &stime)
	_, _ = fmt.Sscanf(fields[23], "%d", &rss)
	return utime + stime, rss * 4096
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
