package main

import (
	"fmt"
	"log"
	"net"

	"google.golang.org/grpc"
	"snffr/manager/internal/decision"
	"snffr/manager/internal/grpc_server"
	"snffr/manager/proto"
)

func main() {
	fmt.Println("snffr Manager Initializing...")

	// Initialise the AI + Decision engine.
	// The model path is relative to the working directory inside the container.
	const modelPath = "models/ids_model.onnx"
	if err := decision.Init(modelPath); err != nil {
		// Non-fatal on startup: the server can still apply rule-based decisions
		// even if the ONNX Runtime library is unavailable. The error is logged
		// prominently so operators can see that AI inference is degraded.
		log.Printf("[main] WARNING: decision engine initialisation failed: %v", err)
		log.Printf("[main] The manager will continue without AI inference.")
	} else {
		log.Printf("[main] Decision engine initialised (model: %s)", modelPath)
	}

	lis, err := net.Listen("tcp", ":50051")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	s := grpc.NewServer()
	srv := grpc_server.NewServer()
	proto.RegisterSnifferServiceServer(s, srv)

	fmt.Println("Listening for Agents on port 50051")
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}