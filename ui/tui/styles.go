package tui

import "github.com/charmbracelet/lipgloss"

var (
	styleBase = lipgloss.NewStyle().Padding(0, 1)
	
	// Single outer border matching Hermes Agent's retro frame
	styleOuter = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("208")). // Amber/Orange border
			Padding(1, 2)
			
	// Bold orange/amber section headings
	styleHermesHeader = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("208")).
			MarginTop(1).
			MarginBottom(0)

	styleInfo  = lipgloss.NewStyle().Foreground(lipgloss.Color("86"))                  // Neon Cyan
	styleWarn  = lipgloss.NewStyle().Foreground(lipgloss.Color("220"))                 // Yellow
	styleCrit  = lipgloss.NewStyle().Foreground(lipgloss.Color("197")).Bold(true)      // Cyber Punk Neon Red
	styleMuted = lipgloss.NewStyle().Foreground(lipgloss.Color("244"))                 // Slate Gray
	styleSuccess = lipgloss.NewStyle().Foreground(lipgloss.Color("118"))               // Lime Green
	
	// Command CLI specific styles
	stylePromptPrefix = lipgloss.NewStyle().Foreground(lipgloss.Color("208")).Bold(true) // Amber prompt
	styleCommandInput = lipgloss.NewStyle().Foreground(lipgloss.Color("15"))
	styleLogSys       = lipgloss.NewStyle().Foreground(lipgloss.Color("86"))            // [SYS] Cyan
	styleLogMem       = lipgloss.NewStyle().Foreground(lipgloss.Color("135"))           // [MEM] Violet
	styleLogPrc       = lipgloss.NewStyle().Foreground(lipgloss.Color("118"))           // [PRC] Lime
	styleLogAlt       = lipgloss.NewStyle().Foreground(lipgloss.Color("197")).Bold(true)// [ALT] Red
	
	// Deprecated / Backwards compatible placeholders
	stylePane = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("244")).
			Padding(0, 1)
	stylePaneActive = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("208")).
			Padding(0, 1)
	styleTitle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("0")).
			Background(lipgloss.Color("244")).
			Padding(0, 1)
	styleTitleActive = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("0")).
			Background(lipgloss.Color("208")).
			Padding(0, 1)
	styleBottom = lipgloss.NewStyle().
			Foreground(lipgloss.Color("15")).
			Background(lipgloss.Color("208")).
			Padding(0, 1)
)

func scoreStyle(score float64) lipgloss.Style {
	switch {
	case score > 70:
		return styleCrit
	case score >= 30:
		return styleWarn
	default:
		return styleSuccess
	}
}
