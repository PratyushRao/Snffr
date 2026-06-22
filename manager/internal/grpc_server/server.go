package grpc_server

import (
	"io"
	"log"
	"snffr/manager/internal/rule_engine"
	"snffr/manager/proto"

	"google.golang.org/grpc"
)

type Server struct {
	proto.UnimplementedSnifferServiceServer
	engine *rule_engine.RuleEngine
}

func NewServer() *Server {
	engine := rule_engine.NewRuleEngine()
	if err := engine.LoadRules("rules.yaml"); err != nil {
		log.Printf("[gRPC Server] Warning: failed to load rules: %v\n", err)
	}
	return &Server{
		engine: engine,
	}
}

func (s *Server) Monitor(stream grpc.BidiStreamingServer[proto.PacketReport, proto.ActionCommand]) error {
	log.Println("[gRPC Server] New agent stream connection established")

	for {
		report, err := stream.Recv()
		if err == io.EOF {
			log.Println("[gRPC Server] Agent closed the stream")
			return nil
		}
		if err != nil {
			log.Printf("[gRPC Server] Stream read error: %v\n", err)
			return err
		}

		// Log incoming packet details
		log.Printf("[gRPC Server] Packet: Agent=%s | %s:%d -> %s:%d | Proto=%s | Size=%d bytes\n",
			report.AgentId,
			report.SrcIp,
			report.SrcPort,
			report.DstIp,
			report.DstPort,
			report.Protocol,
			report.Length,
		)

		// Evaluate packet against loaded rules
		if cmd, matched := s.engine.Evaluate(report); matched {
			log.Printf("[gRPC Server] RULE MATCHED: Action=%v | TargetIP=%s | Reason=%s\n",
				cmd.Action,
				cmd.TargetIp,
				cmd.Reason,
			)

			if err := stream.Send(cmd); err != nil {
				log.Printf("[gRPC Server] Failed to send ActionCommand to agent: %v\n", err)
			}
		}
	}
}
