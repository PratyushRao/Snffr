# How to do Stuff
### Delete this file before making the project public!!!

We'll split the project into 3 sections - agent, manager, and dashboard. I think the dashboard takes least priority for now since its the easiest. This is the file structure for now:

```
snffr/
├── docker-compose.yml
├── proto/
│   └── snffr.proto             # Protobuf definitions for gRPC communication
├── agent/                      # --- RUST AGENT ---
│   ├── Cargo.toml
│   ├── src/
│   │   ├── main.rs             # Entry point: initializes capture & gRPC
│   │   ├── capture.rs          # libpcap / pcap logic
│   │   ├── filter.rs           # local traffic pre-processing
│   │   └── responder.rs        # iptables / nftables stuff
│   └── Dockerfile
├── manager/                    # --- GO MANAGER ---
│   ├── go.mod
│   ├── main.go
│   ├── internal/
│   │   ├── grpc_server/        # Receives data from Agents
│   │   ├── rule_engine/        # Signature & threshold matching
│   │   └── ws_hub/             # WebSocket logic for the Dashboard
│   └── Dockerfile
└── dashboard/
    ├── package.json
    ├── src/
    │   ├── components/         # All the fun stuff
    │   ├── hooks/              # WebSockets here
    │   └── types/              # TS interfaces matching the Protobufs
    └── Dockerfile
```

I started by making snffr.proto first. It's a **[protocol buffer](protobuf.dev/overview/)** schema, which is basically a data serliazation/deserialization standard set by Google gRPC for communication. (imagine JSON if it was actually good). For now I'll just paste whatever Gemini spits out in snffr.proto because im not smart enough to write one on my own.

Next most important thing is the agent, these guys basically keep watching whatevers going on and send any potential threats to manager. We'll use Rust for this. 
...(to be continued)

As for the manager, we'll be using a gRPC server to stay connected to everything and goroutines for concurrency. We can start by checking for SYN Floods and Port Scans initially, then add more attack signatures later. This part of the project is gonna get massive.