package tui

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"snffr/manager/internal/events"
)

// Styling
var (
	baseStyle = lipgloss.NewStyle().Padding(1)

	headerStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("205")).
			Bold(true).
			MarginBottom(1)

	panelStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("62")).
			Padding(0, 1)

	panelTitleStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("86")).
			Bold(true).
			MarginBottom(1).
			Underline(true)

	alertRuleStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("11")).Bold(true) // Yellow for rules
	alertAIStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("9")).Bold(true)  // Red for AI
	agentIDStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("14"))            // Cyan
	logInfoStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("241"))           // Gray
)

type AgentState struct {
	ID        string
	Connected time.Time
	Packets   int
	Bytes     int
}

type AlertItem struct {
	Time     time.Time
	Source   string
	Action   string
	TargetIP string
	Reason   string
}

type Model struct {
	activeAgents map[string]*AgentState
	alerts       []AlertItem
	logs         []string
	
	viewport    viewport.Model
	alertHeight int
	logHeight   int
	width       int
	height      int
	ready       bool
}

func NewModel() *Model {
	return &Model{
		activeAgents: make(map[string]*AgentState),
		alerts:       make([]AlertItem, 0),
		logs:         make([]string, 0),
	}
}

func (m *Model) Init() tea.Cmd {
	// Start a command that reads from the event bus
	return waitForEvent
}

type tickEvent struct{}

func waitForEvent() tea.Msg {
	ev := <-events.Bus
	return ev
}

func (m *Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var (
		cmd  tea.Cmd
		cmds []tea.Cmd
	)

	switch msg := msg.(type) {
	case tea.KeyMsg:
		if msg.String() == "ctrl+c" || msg.String() == "q" {
			return m, tea.Quit
		}

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.alertHeight = (msg.Height - 10) / 2
		if m.alertHeight < 5 {
			m.alertHeight = 5
		}
		m.logHeight = msg.Height - m.alertHeight - 10
		if m.logHeight < 5 {
			m.logHeight = 5
		}

		if !m.ready {
			m.viewport = viewport.New(msg.Width-30, m.logHeight)
			m.ready = true
		} else {
			m.viewport.Width = msg.Width - 30
			m.viewport.Height = m.logHeight
		}

	// Handle events
	case events.AgentConnected:
		m.activeAgents[msg.AgentID] = &AgentState{
			ID:        msg.AgentID,
			Connected: time.Now(),
		}
		m.addLog(fmt.Sprintf("Agent Connected: %s", msg.AgentID))
		cmds = append(cmds, waitForEvent)

	case events.AgentDisconnected:
		delete(m.activeAgents, msg.AgentID)
		m.addLog(fmt.Sprintf("Agent Disconnected: %s", msg.AgentID))
		cmds = append(cmds, waitForEvent)

	case events.PacketReceived:
		if agent, ok := m.activeAgents[msg.AgentID]; ok {
			agent.Packets++
			agent.Bytes += msg.Length
		}
		cmds = append(cmds, waitForEvent)

	case events.AlertFired:
		m.alerts = append(m.alerts, AlertItem{
			Time:     time.Now(),
			Source:   msg.Source,
			Action:   msg.Action,
			TargetIP: msg.TargetIP,
			Reason:   msg.Reason,
		})
		// Keep last 100 alerts
		if len(m.alerts) > 100 {
			m.alerts = m.alerts[1:]
		}
		m.addLog(fmt.Sprintf("[%s ALERT] %s - %s", msg.Source, msg.TargetIP, msg.Action))
		cmds = append(cmds, waitForEvent)

	case events.LogMessage:
		m.addLog(msg.Message)
		cmds = append(cmds, waitForEvent)
	}

	m.viewport, cmd = m.viewport.Update(msg)
	cmds = append(cmds, cmd)

	return m, tea.Batch(cmds...)
}

func (m *Model) addLog(msg string) {
	timestamp := time.Now().Format("15:04:05")
	m.logs = append(m.logs, fmt.Sprintf("%s %s", logInfoStyle.Render(timestamp), msg))
	if len(m.logs) > 1000 {
		m.logs = m.logs[1:]
	}
	if m.ready {
		isAtBottom := m.viewport.AtBottom()
		m.viewport.SetContent(strings.Join(m.logs, "\n"))
		if isAtBottom {
			m.viewport.GotoBottom()
		}
	}
}

func (m *Model) View() string {
	if !m.ready {
		return "\n  Initializing..."
	}

	header := headerStyle.Render("🛡️ Snffr IDS Manager - Live Dashboard")

	// Left panel: Agents
	var agentsText string
	if len(m.activeAgents) == 0 {
		agentsText = "No active agents."
	} else {
		for id, state := range m.activeAgents {
			uptime := time.Since(state.Connected).Round(time.Second)
			agentsText += fmt.Sprintf("ID: %s\nUp: %s\nPkts: %d\nKB: %.1f\n\n",
				agentIDStyle.Render(id),
				uptime.String(),
				state.Packets,
				float64(state.Bytes)/1024.0,
			)
		}
	}
	
	agentsInnerHeight := m.height - 8
	if agentsInnerHeight < 1 {
		agentsInnerHeight = 1
	}
	agentsContent := lipgloss.NewStyle().MaxHeight(agentsInnerHeight).MaxWidth(25).Render(
		lipgloss.JoinVertical(lipgloss.Left,
			panelTitleStyle.Render("📡 Agents"),
			agentsText,
		),
	)
	agentsPanel := panelStyle.Width(25).Height(m.height - 6).MaxHeight(m.height - 6).Render(agentsContent)

	// Right top: Alerts
	var alertsText string
	if len(m.alerts) == 0 {
		alertsText = "No alerts detected."
	} else {
		start := len(m.alerts) - m.alertHeight
		if start < 0 {
			start = 0
		}
		for _, a := range m.alerts[start:] {
			ts := logInfoStyle.Render(a.Time.Format("15:04:05"))
			var src string
			if a.Source == "AI" {
				src = alertAIStyle.Render("[AI]")
			} else {
				src = alertRuleStyle.Render("[RULE]")
			}
			act := lipgloss.NewStyle().Foreground(lipgloss.Color("1")).Render(a.Action)
			ip := lipgloss.NewStyle().Foreground(lipgloss.Color("3")).Render(a.TargetIP)
			
			alertsText += fmt.Sprintf("%s %s %s on %s - %s\n", ts, src, act, ip, a.Reason)
		}
	}
	
	alertsInnerHeight := m.alertHeight - 2
	if alertsInnerHeight < 1 {
		alertsInnerHeight = 1
	}
	alertsContent := lipgloss.NewStyle().MaxHeight(alertsInnerHeight).MaxWidth(m.width - 34).Render(
		lipgloss.JoinVertical(lipgloss.Left,
			panelTitleStyle.Render("⚠️ Recent Alerts"),
			alertsText,
		),
	)
	alertsPanel := panelStyle.Width(m.width - 32).Height(m.alertHeight).MaxHeight(m.alertHeight).Render(alertsContent)

	// Right bottom: Logs
	logsInnerHeight := m.logHeight - 2
	if logsInnerHeight < 1 {
		logsInnerHeight = 1
	}
	logsContent := lipgloss.NewStyle().MaxHeight(logsInnerHeight).MaxWidth(m.width - 34).Render(
		lipgloss.JoinVertical(lipgloss.Left,
			panelTitleStyle.Render("📜 System Logs"),
			m.viewport.View(),
		),
	)
	logsPanel := panelStyle.Width(m.width - 32).Height(m.logHeight).MaxHeight(m.logHeight).Render(logsContent)

	rightSide := lipgloss.JoinVertical(lipgloss.Left, alertsPanel, logsPanel)
	mainView := lipgloss.JoinHorizontal(lipgloss.Top, agentsPanel, "  ", rightSide)

	footer := lipgloss.NewStyle().Foreground(lipgloss.Color("241")).MarginTop(1).Render(
		"Press 'q' or 'ctrl+c' to quit",
	)

	// Strict bounding for the entire view to prevent ANY terminal scrolling
	finalView := baseStyle.Render(lipgloss.JoinVertical(lipgloss.Left, header, mainView, footer))
	return lipgloss.NewStyle().MaxHeight(m.height).MaxWidth(m.width).Render(finalView)
}
