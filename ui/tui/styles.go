package tui

import "github.com/charmbracelet/lipgloss"

var (
	styleBase = lipgloss.NewStyle().Padding(0, 1)
	stylePane = lipgloss.NewStyle().
			Border(lipgloss.NormalBorder()).
			BorderForeground(lipgloss.Color("240")).
			Padding(0, 1)
	styleTitle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("15")).
			Background(lipgloss.Color("236")).
			Padding(0, 1)
	styleBottom = lipgloss.NewStyle().
			Foreground(lipgloss.Color("250")).
			Background(lipgloss.Color("236")).
			Padding(0, 1)
	styleInfo = lipgloss.NewStyle().Foreground(lipgloss.Color("39"))
	styleWarn = lipgloss.NewStyle().Foreground(lipgloss.Color("220"))
	styleCrit = lipgloss.NewStyle().Foreground(lipgloss.Color("196")).Bold(true)
	styleMuted = lipgloss.NewStyle().Foreground(lipgloss.Color("244"))
)

func scoreStyle(score float64) lipgloss.Style {
	switch {
	case score > 70:
		return styleCrit
	case score >= 30:
		return styleWarn
	default:
		return lipgloss.NewStyle().Foreground(lipgloss.Color("42"))
	}
}
