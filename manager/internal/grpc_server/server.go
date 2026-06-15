package grpc_server

import (
	"io"
	"log"
	"snffr/manager/proto"

	"google.golang.org/grpc"
)

type Server struct {
	proto.UnimplementedSnifferServiceServer
}

func NewServer() *Server {
	return &Server{}
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

		// Log the incoming packet details
		log.Printf("[gRPC Server] Packet: Agent=%s | %s:%d -> %s:%d | Proto=%s | Size=%d bytes\n",
			report.AgentId,
			report.SrcIp,
			report.SrcPort,
			report.DstIp,
			report.DstPort,
			report.Protocol,
			report.Length,
		)
	}
}
