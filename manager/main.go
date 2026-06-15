package main

import (
	"fmt"
	"log"
	"net"

	"google.golang.org/grpc"
	"snffr/manager/internal/grpc_server"
	"snffr/manager/proto"
)

func main() {
	fmt.Println("snffr Manager Initializing...")

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