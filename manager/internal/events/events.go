package events

type AgentConnected struct {
	AgentID string
}

type AgentDisconnected struct {
	AgentID string
}

type PacketReceived struct {
	AgentID  string
	Protocol string
	Length   int
}

type AlertFired struct {
	Source   string // "Rule" or "AI"
	Action   string // "BLOCK", "RATE_LIMIT"
	TargetIP string
	Reason   string
}

type LogMessage struct {
	Message string
}

// Global event channel for simple decoupling
var Bus = make(chan interface{}, 1000)

func Publish(e interface{}) {
	select {
	case Bus <- e:
	default:
		// If channel is full, drop event to avoid blocking
	}
}
