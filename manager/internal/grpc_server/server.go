package grpc_server

import (
	"fmt"
	"io"
	"log"

	"snffr/manager/internal/aggregator"
	"snffr/manager/internal/decision"
	"snffr/manager/internal/events"
	"snffr/manager/internal/rule_engine"
	"snffr/manager/proto"

	"google.golang.org/grpc"
)

// ─────────────────────────────────────────────────────────────────────────────
// Response policy constants
// ─────────────────────────────────────────────────────────────────────────────

const (
	// blockDurationSeconds is how long a BLOCK action persists on the agent.
	blockDurationSeconds uint32 = 300 // 5 minutes

	// rateLimitDurationSeconds is how long a RATE_LIMIT action persists.
	rateLimitDurationSeconds uint32 = 60 // 1 minute

	// rateLimitPPS is the max packets-per-second allowed for a rate-limited IP.
	rateLimitPPS uint32 = 100
)

// ─────────────────────────────────────────────────────────────────────────────
// Server
// ─────────────────────────────────────────────────────────────────────────────

// Server is the gRPC service implementation for the Sniffer service.
// It receives a stream of PacketReports from each connected agent, evaluates
// them through two parallel engines, and streams ActionCommands back.
//
// Two evaluation paths run for every packet:
//  1. Signature / threshold rule engine (rule_engine) — fires immediately on
//     every packet; catches known patterns like SSH brute-force, ICMP floods,
//     and payload signatures.
//  2. AI flow engine (aggregator → decision) — accumulates packets into flow
//     windows, computes FlowFeatures, and calls the ONNX Isolation Forest
//     model; catches statistical anomalies that the rule engine misses.
type Server struct {
	proto.UnimplementedSnifferServiceServer

	// ruleEngine evaluates per-packet signature and threshold rules from rules.yaml.
	ruleEngine *rule_engine.RuleEngine

	// agg groups incoming packets into flow windows and emits FlowResults when
	// a window is complete. One shared aggregator services all agent streams.
	agg *aggregator.Aggregator
}

// NewServer creates a fully initialised Server. The YAML rule engine loads
// rules from rules.yaml (logs a warning if the file is missing but does not
// crash — the AI engine runs independently).
func NewServer() *Server {
	engine := rule_engine.NewRuleEngine()
	if err := engine.LoadRules("rules.yaml"); err != nil {
		log.Printf("[gRPC Server] Warning: failed to load rules: %v\n", err)
	}

	agg := aggregator.NewAggregator()

	srv := &Server{
		ruleEngine: engine,
		agg:        agg,
	}

	return srv
}

// Monitor is the bidirectional streaming RPC handler.
// One goroutine per connected agent calls this method.
func (s *Server) Monitor(stream grpc.BidiStreamingServer[proto.PacketReport, proto.ActionCommand]) error {
	events.Publish(events.LogMessage{Message: "New agent stream connection established"})

	// Drain the aggregator's async results channel (time-window expirations)
	// in a dedicated goroutine for this stream so every flow gets evaluated
	// even when traffic stops mid-window.
	stopDrain := make(chan struct{})
	go func() {
		for {
			select {
			case <-stopDrain:
				return
			case result, ok := <-s.agg.Results():
				if !ok {
					return
				}
				s.evaluateAndRespond(stream, result)
			}
		}
	}()
	defer close(stopDrain)

	agentConnected := false
	var currentAgentId string

	for {
		report, err := stream.Recv()
		if err == io.EOF {
			if agentConnected {
				events.Publish(events.AgentDisconnected{AgentID: currentAgentId})
			}
			events.Publish(events.LogMessage{Message: "Agent closed the stream"})
			return nil
		}
		if err != nil {
			if agentConnected {
				events.Publish(events.AgentDisconnected{AgentID: currentAgentId})
			}
			events.Publish(events.LogMessage{Message: fmt.Sprintf("Stream read error: %v", err)})
			return err
		}

		if !agentConnected {
			currentAgentId = report.AgentId
			agentConnected = true
			events.Publish(events.AgentConnected{AgentID: currentAgentId})
		}

		events.Publish(events.PacketReceived{
			AgentID:  report.AgentId,
			Protocol: report.Protocol,
			Length:   int(report.Length),
		})

		// ── Path 1: Immediate signature / threshold rules ─────────────────────
		if cmd, matched := s.ruleEngine.Evaluate(report); matched {
			events.Publish(events.AlertFired{
				Source:   "Rule",
				Action:   cmd.Action.String(),
				TargetIP: cmd.TargetIp,
				Reason:   cmd.Reason,
			})

			if err := stream.Send(cmd); err != nil {
				events.Publish(events.LogMessage{Message: fmt.Sprintf("Failed to send rule ActionCommand: %v", err)})
			}
		}

		// ── Path 2: AI flow engine (packet-count threshold path) ──────────────
		if result := s.agg.Ingest(report); result != nil {
			s.evaluateAndRespond(stream, result)
		}
	}
}

// evaluateAndRespond calls the AI decision engine for a completed flow window
// and, if the decision is not Allow, streams an ActionCommand back to the agent.
func (s *Server) evaluateAndRespond(
	stream grpc.BidiStreamingServer[proto.PacketReport, proto.ActionCommand],
	result *aggregator.FlowResult,
) {
	d, totalRisk, err := decision.EvaluateFlow(result.Features)
	if err != nil {
		// Inference failure is non-fatal — log and move on.
		events.Publish(events.LogMessage{Message: fmt.Sprintf("AI inference error for flow %s: %v", result.Key, err)})
		return
	}

	// AI EVAL: flow=...
	// We could publish a trace event if we wanted, but let's just log it or ignore it if Allow.
	// For now, if not Allow, it's an alert.

	cmd := decisionToCommand(d, result.SrcIP, totalRisk)
	if cmd == nil {
		return // Allow — no action needed
	}

	events.Publish(events.AlertFired{
		Source:   "AI",
		Action:   cmd.Action.String(),
		TargetIP: cmd.TargetIp,
		Reason:   cmd.Reason,
	})

	if err := stream.Send(cmd); err != nil {
		events.Publish(events.LogMessage{Message: fmt.Sprintf("Failed to send AI ActionCommand: %v", err)})
	}
}

// decisionToCommand maps a Decision to a proto.ActionCommand.
// Returns nil for Allow (no command to send).
func decisionToCommand(d decision.Decision, srcIP string, totalRisk int) *proto.ActionCommand {
	switch d {
	case decision.Block:
		return &proto.ActionCommand{
			Action:          proto.ActionCommand_BLOCK,
			TargetIp:        srcIP,
			Reason:          fmt.Sprintf("AI+Rule risk score %d/100 — anomalous flow detected", totalRisk),
			DurationSeconds: blockDurationSeconds,
		}
	case decision.RateLimit:
		return &proto.ActionCommand{
			Action:          proto.ActionCommand_RATE_LIMIT,
			TargetIp:        srcIP,
			Reason:          fmt.Sprintf("AI+Rule risk score %d/100 — suspicious flow rate-limited", totalRisk),
			DurationSeconds: rateLimitDurationSeconds,
			RateLimitPps:    rateLimitPPS,
		}
	default:
		return nil
	}
}
