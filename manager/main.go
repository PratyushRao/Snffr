package main

import (
	"log"
	"net"
	"os"

	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"google.golang.org/grpc"
	"snffr/manager/internal/decision"
	"snffr/manager/internal/events"
	"snffr/manager/internal/grpc_server"
	"snffr/manager/internal/tui"
	"snffr/manager/proto"
)

type EventLogWriter struct{}

func (w EventLogWriter) Write(p []byte) (n int, err error) {
	msg := strings.TrimSpace(string(p))
	if msg != "" {
		events.Publish(events.LogMessage{Message: msg})
	}
	return len(p), nil
}

func main() {
	// Redirect standard log to the event bus
	log.SetOutput(EventLogWriter{})
	log.SetFlags(0) // Remove date/time since TUI adds it

	const modelPath = "models/ids_model.onnx"
	if err := decision.Init(modelPath); err != nil {
		events.Publish(events.LogMessage{Message: "WARNING: decision engine initialisation failed: " + err.Error()})
		events.Publish(events.LogMessage{Message: "The manager will continue without AI inference."})
	} else {
		events.Publish(events.LogMessage{Message: "Decision engine initialised (model: " + modelPath + ")"})
	}

	lis, err := net.Listen("tcp", ":50051")
	if err != nil {
		// Fatal error, TUI not started yet
		log.Fatalf("failed to listen: %v", err)
	}

	s := grpc.NewServer()
	srv := grpc_server.NewServer()
	proto.RegisterSnifferServiceServer(s, srv)

	go func() {
		events.Publish(events.LogMessage{Message: "Listening for Agents on port 50051"})
		if err := s.Serve(lis); err != nil {
			events.Publish(events.LogMessage{Message: "failed to serve: " + err.Error()})
		}
	}()

	// Start Bubbletea TUI
	p := tea.NewProgram(tui.NewModel(), tea.WithAltScreen(), tea.WithMouseCellMotion())
	if _, err := p.Run(); err != nil {
		log.Printf("Alas, there's been an error: %v", err)
		os.Exit(1)
	}
}