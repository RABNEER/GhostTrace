package tui

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/textinput"
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
	
	// CLI console specific attributes
	textInput   textinput.Model
	logs        []string
	activePanel int  // 0 = Telemetry Logs, 1 = Threat Radar
	logScroll   int  // Scroll offset for telemetry logs
	quitting    bool // Signal program termination safely
}

type alertMsg alert.Alert
type statsMsg Stats
type tickMsg time.Time

func Run(ctx context.Context, g *graph.ProcessGraph, alertCh <-chan alert.Alert, statsCh <-chan Stats) error {
	ti := textinput.New()
	ti.Placeholder = "Type command... (e.g. help, kill 4242, export, clear)"
	ti.Prompt = ""
	ti.PromptStyle = stylePromptPrefix
	ti.TextStyle = styleCommandInput
	
	model := &Dashboard{
		graph:     g,
		started:   time.Now(),
		textInput: ti,
	}
	model.addLog("[SYS] GhostTrace kernel telemetry subsystem initialized")
	model.addLog("[SYS] AVX2 signature scanner loaded (4 patterns active)")
	model.addLog("[SYS] Terminal dashboard bound. Press ':' or '/' to enter command mode.")

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
	return tea.Batch(tickCmd(), textinput.Blink)
}

func (d *Dashboard) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd
	
	// Route keystrokes directly to the CLI command input text bubble if it has focus
	if d.textInput.Focused() {
		switch m := msg.(type) {
		case tea.KeyMsg:
			switch m.String() {
			case "enter":
				d.handleCommand(d.textInput.Value())
				d.textInput.SetValue("")
				d.textInput.Blur()
				return d, nil
			case "esc":
				d.textInput.SetValue("")
				d.textInput.Blur()
				return d, nil
			}
		}
		d.textInput, cmd = d.textInput.Update(msg)
		return d, cmd
	}

	switch m := msg.(type) {
	case tea.WindowSizeMsg:
		d.width = m.Width
		d.height = m.Height
	case tea.KeyMsg:
		switch m.String() {
		case ":", "/":
			d.textInput.Focus()
			return d, textinput.Blink
		default:
			return d.handleKey(m)
		}
	case alertMsg:
		if !d.paused {
			a := alert.Alert(m)
			d.alerts = append(d.alerts, a)
			d.addLog(fmt.Sprintf("[ALT] ALERT: %s PID %d (%s) - %s", a.Severity, a.PID, a.Comm, a.Detail))
		}
	case statsMsg:
		d.stats = Stats(m)
		if d.stats.EventsPerSec > 0 {
			d.addLog(fmt.Sprintf("[SYS] Telemetry ingestion loop: processing %d events/sec", d.stats.EventsPerSec))
		}
	case tickMsg:
		d.stats.Uptime = time.Since(d.started)
		d.stats.SelfCPUJiffies, d.stats.SelfMemoryBytes = readSelfStat()
		return d, tickCmd()
	}
	
	if d.quitting {
		return d, tea.Quit
	}
	
	return d, nil
}

func (d *Dashboard) View() string {
	if d.width == 0 || d.height == 0 {
		return "initializing..."
	}

	// Dynamic layout adjustment for terminal size
	showASCIIHeader := d.height >= 24
	headerHeight := 0
	if showASCIIHeader {
		headerHeight = 8 // ASCII title + line separator
	}

	bodyHeight := d.height - headerHeight - 4
	if bodyHeight < 6 {
		bodyHeight = 6
	}

	leftW := 26
	rightW := d.width - leftW - 6
	if rightW < 30 {
		rightW = 30
	}

	// 1. Retro Block ASCII Header
	var asciiHeader string
	if showASCIIHeader {
		banner := "" +
			" ██████╗ ██╗  ██╗ ██████╗ ██████╗████████╗██████╗  █████╗  ██████╗███████╗\n" +
			"██╔════╝ ██║  ██║██╔═══██╗██╔════╝╚══██╔══╝██╔══██╗██╔══██╗██╔════╝██╔════╝\n" +
			"██║  ███╗███████║██║   ██║███████╗   ██║   ██████╔╝███████║██║     █████╗  \n" +
			"██║   ██║██╔══██║██║   ██║╚════██║   ██║   ██╔══██╗██╔══██║██║     ██╔══╝  \n" +
			"╚██████╔╝██║  ██║╚██████╔╝███████║   ██║   ██║  ██║██║  ██║╚██████╗███████╗\n" +
			" ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚══════╝"
		headerColorized := stylePromptPrefix.Render(banner)
		
		sub := fmt.Sprintf("───── GhostTrace Kernel Telemetry v1.2.0 • mode: windows ─────")
		paddingSize := (d.width - lipgloss.Width(sub)) / 2
		if paddingSize < 0 {
			paddingSize = 0
		}
		subCentered := strings.Repeat(" ", paddingSize) + styleMuted.Render(sub)
		asciiHeader = headerColorized + "\n" + subCentered + "\n"
	}

	// 2. Left Column (ASCII Ghost + Host Specs)
	logo := "\n" +
		"     .---.  \n" +
		"    /     \\ \n" +
		"   | () () |\n" +
		"    \\  ^  / \n" +
		"     |||||  \n" +
		"     |||||  "
	logoStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("86")) // Cyan
	
	specs := fmt.Sprintf("\n\n"+
		" %s\n"+
		" %s\n\n"+
		" %s\n"+
		" %s\n"+
		" %s\n",
		stylePromptPrefix.Render("ghosttrace v1.2.0"),
		styleMuted.Render("windows-x64 • local"),
		styleMuted.Render("Uptime: "+d.stats.Uptime.Truncate(time.Second).String()),
		styleMuted.Render("RSS:    "+formatBytes(d.stats.SelfMemoryBytes)),
		styleMuted.Render("Events: "+fmt.Sprint(d.stats.TotalProcesses)),
	)
	leftColumnView := logoStyle.Render(logo) + specs

	// 3. Right Column (Operations + Threat Radar + Telemetry Log Feed)
	rows := d.graph.Snapshot()
	d.stats.TotalProcesses = len(rows)

	// Available Operations Section
	controlsTitle := styleHermesHeader.Render("Available Operations")
	controlsText := styleMuted.Render("  [:] Command prompt  |  [Tab] Switch focus  |  [j/k] Scroll  |  [q]uit")

	// Dynamic layout calculation for Right Column feeds
	availableHeight := bodyHeight - 6
	if availableHeight < 4 {
		availableHeight = 4
	}
	threatRadarHeight := availableHeight * 40 / 100
	if threatRadarHeight < 2 {
		threatRadarHeight = 2
	}
	logHeight := availableHeight - threatRadarHeight
	if logHeight < 2 {
		logHeight = 2
	}

	// Threat Radar Section
	threatTitleText := "Active Threat Radar Index"
	if d.activePanel == 1 {
		threatTitleText += " • (Focused)"
	}
	threatTitle := styleHermesHeader.Render(threatTitleText)
	threatRadarView := views.RenderProcesses(rows, d.selectedP, threatRadarHeight, func(score float64, s string) string {
		return scoreStyle(score).Render(s)
	})

	// Log Telemetry Section
	logTitleText := "Telemetry Log Terminal Feed"
	if d.activePanel == 0 {
		logTitleText += " • (Focused)"
	}
	logTitle := styleHermesHeader.Render(logTitleText)

	var consoleLogLines []string
	logOffset := len(d.logs) - logHeight - d.logScroll
	if logOffset < 0 {
		logOffset = 0
	}
	endOffset := logOffset + logHeight
	if endOffset > len(d.logs) {
		endOffset = len(d.logs)
	}
	for i := logOffset; i < endOffset; i++ {
		consoleLogLines = append(consoleLogLines, d.logs[i])
	}
	for len(consoleLogLines) < logHeight {
		consoleLogLines = append(consoleLogLines, "")
	}
	consoleLogView := strings.Join(consoleLogLines, "\n")

	rightColumnView := controlsTitle + "\n" + controlsText + "\n" +
		threatTitle + "\n" + threatRadarView + "\n" +
		logTitle + "\n" + consoleLogView

	// 4. Command Input Row
	var bottomLine string
	if d.textInput.Focused() {
		bottomLine = "\n" + stylePromptPrefix.Render("ghosttrace > ") + d.textInput.View()
	} else {
		bottomLine = "\n" + styleMuted.Render("ghosttrace > (Press ':' or '/' to enter command mode)")
	}

	// Join Columns horizontally and apply the single retro Amber Border frame
	bodyJoined := lipgloss.JoinHorizontal(lipgloss.Top, leftColumnView, "   ", rightColumnView)
	outerPanel := styleOuter.Width(d.width - 6).Height(bodyHeight + 2).Render(bodyJoined + bottomLine)

	return asciiHeader + outerPanel
}

func (d *Dashboard) handleKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "q", "ctrl+c":
		return d, tea.Quit
	case "tab":
		d.activePanel = 1 - d.activePanel
	case "down", "j":
		if d.activePanel == 0 {
			// Scroll log feed down (closer to latest)
			d.logScroll -= 3
			if d.logScroll < 0 {
				d.logScroll = 0
			}
		} else {
			// Scroll process index down
			d.selectedP++
			numProcs := len(d.graph.Snapshot())
			if d.selectedP >= numProcs {
				d.selectedP = numProcs - 1
			}
			if d.selectedP < 0 {
				d.selectedP = 0
			}
		}
	case "up", "k":
		if d.activePanel == 0 {
			// Scroll log feed up (older history)
			d.logScroll += 3
			maxScroll := len(d.logs) - d.logHeight()
			if maxScroll < 0 {
				maxScroll = 0
			}
			if d.logScroll > maxScroll {
				d.logScroll = maxScroll
			}
		} else {
			// Scroll process index up
			d.selectedP--
			if d.selectedP < 0 {
				d.selectedP = 0
			}
		}
	case "enter":
		d.expanded = !d.expanded
	case "p":
		d.paused = !d.paused
		if d.paused {
			d.addLog("Monitor stream paused.")
		} else {
			d.addLog("Monitor stream active.")
		}
	case "e":
		if err := d.exportAlerts(); err != nil {
			d.addLog(fmt.Sprintf("Error: export failed: %s", err.Error()))
		} else {
			d.addLog("Success: exported alerts to local JSON file.")
		}
	}
	return d, nil
}

func (d *Dashboard) handleCommand(rawCmd string) {
	cmd := strings.TrimSpace(rawCmd)
	if cmd == "" {
		return
	}
	parts := strings.Fields(cmd)
	d.addLog(fmt.Sprintf("> %s", cmd))
	switch parts[0] {
	case "help", "?":
		d.addLog("Available commands:")
		d.addLog("  help, ?      Show this command list")
		d.addLog("  kill <pid>   Terminate the specified process")
		d.addLog("  clear        Clear console log history")
		d.addLog("  pause        Pause alert capture stream")
		d.addLog("  resume       Resume alert capture stream")
		d.addLog("  export       Export triggered alerts to JSON")
		d.addLog("  quit, exit   Exit GhostTrace console")
	case "kill":
		if len(parts) < 2 {
			d.addLog("Error: 'kill' requires a target PID (e.g., kill 1234)")
			return
		}
		var pid int
		if _, err := fmt.Sscanf(parts[1], "%d", &pid); err != nil {
			d.addLog(fmt.Sprintf("Error: invalid PID '%s'", parts[1]))
			return
		}
		proc, err := os.FindProcess(pid)
		if err != nil {
			d.addLog(fmt.Sprintf("Error: process PID %d not found", pid))
			return
		}
		if err := proc.Kill(); err != nil {
			d.addLog(fmt.Sprintf("Error: failed to kill PID %d: %s", pid, err.Error()))
		} else {
			d.addLog(fmt.Sprintf("Success: sent SIGKILL to PID %d", pid))
		}
	case "clear":
		d.logs = nil
	case "pause":
		d.paused = true
		d.addLog("Monitor stream paused.")
	case "resume":
		d.paused = false
		d.addLog("Monitor stream active.")
	case "export":
		if err := d.exportAlerts(); err != nil {
			d.addLog(fmt.Sprintf("Error: export failed: %s", err.Error()))
		} else {
			d.addLog("Success: exported alerts to local JSON file.")
		}
	case "quit", "exit":
		d.quitting = true
	default:
		d.addLog(fmt.Sprintf("Command not recognized: '%s'. Type 'help' for options.", parts[0]))
	}
}

func (d *Dashboard) addLog(msg string) {
	d.logScroll = 0
	tStr := time.Now().Format("15:04:05")
	var prefix string
	if strings.HasPrefix(msg, "[SYS]") {
		prefix = styleLogSys.Render("[SYS]")
		msg = msg[5:]
	} else if strings.HasPrefix(msg, "[MEM]") {
		prefix = styleLogMem.Render("[MEM]")
		msg = msg[5:]
	} else if strings.HasPrefix(msg, "[PRC]") {
		prefix = styleLogPrc.Render("[PRC]")
		msg = msg[5:]
	} else if strings.HasPrefix(msg, "[ALT]") {
		prefix = styleLogAlt.Render("[ALT]")
		msg = msg[5:]
	} else if strings.HasPrefix(msg, ">") {
		prefix = stylePromptPrefix.Render("[CMD]")
		msg = msg[1:]
	} else {
		prefix = styleMuted.Render("[LOG]")
	}
	
	line := fmt.Sprintf("%s %s %s", styleMuted.Render(tStr), prefix, msg)
	d.logs = append(d.logs, line)
	if len(d.logs) > 100 {
		d.logs = d.logs[1:]
	}
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

func formatBytes(b uint64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
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

func (d *Dashboard) logHeight() int {
	showASCIIHeader := d.height >= 24
	headerHeight := 0
	if showASCIIHeader {
		headerHeight = 8
	}
	bodyHeight := d.height - headerHeight - 4
	if bodyHeight < 6 {
		bodyHeight = 6
	}
	availableHeight := bodyHeight - 6
	if availableHeight < 4 {
		availableHeight = 4
	}
	threatRadarHeight := availableHeight * 40 / 100
	if threatRadarHeight < 2 {
		threatRadarHeight = 2
	}
	lh := availableHeight - threatRadarHeight
	if lh < 2 {
		lh = 2
	}
	return lh
}
