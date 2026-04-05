package main

import (
    "fmt"
    "log"
    "net"

    "google.golang.org/grpc"
    // "snffr/manager/internal/grpc_server" 
)

func main() {
    fmt.Println("snffr Manager Initializing...")

    lis, err := net.Listen("tcp", ":50051")
    if err != nil {
        log.Fatalf("failed to listen: %v", err)
    }
    
    s := grpc.NewServer()
    // register your snffr service here later
    
    fmt.Println("Listening for Rust Agents on port 50051")
    if err := s.Serve(lis); err != nil {
        log.Fatalf("failed to serve: %v", err)
    }
}