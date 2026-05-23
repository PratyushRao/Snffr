# Roadmap: Distributed gRPC Integration

This roadmap outlines the steps to connect the Rust Agent to the Go Manager using gRPC, forming the core of the distributed architecture.

## Phase 1: Go Manager gRPC Setup
*   **Goal:** Generate Go protobuf code and start the gRPC listener.
*   **Tasks:**
    1.  Install `protoc` and the Go plugins (`protoc-gen-go`, `protoc-gen-go-grpc`).
    2.  Run `protoc` to generate Go code from `proto/snffr.proto`.
    3.  Implement the `SnifferServiceServer` interface in `manager/internal/grpc_server`.
    4.  Update `manager/main.go` to register the service and log incoming `PacketReport` streams.

## Phase 2: Rust Agent gRPC Setup
*   **Goal:** Generate Rust protobuf code and establish a client connection.
*   **Tasks:**
    1.  Add `tonic`, `prost`, and `tokio` dependencies to the Agent's `Cargo.toml`.
    2.  Update `agent/build.rs` to compile the `snffr.proto` file into Rust code during the build process.
    3.  Initialize a Tokio async runtime in `agent/src/main.rs`.
    4.  Create a gRPC client channel connecting to `localhost:50051` (the Manager).

## Phase 3: The Data Pipeline
*   **Goal:** Stream parsed packets from the capture engine to the Manager.
*   **Tasks:**
    1.  Bridge the synchronous `libpcap` thread with the asynchronous `tonic` gRPC client using Tokio channels (`tokio::sync::mpsc`).
    2.  In the `parser.rs` processing loop, map the `ParsedPacket` struct to the generated Protobuf `PacketReport` message.
    3.  Call the `Monitor` RPC method to send a continuous stream of `PacketReport` messages to the Go Manager.

## Phase 4: Testing & Verification
*   **Goal:** Confirm end-to-end communication.
*   **Tasks:**
    1.  Start the Go Manager.
    2.  Start the Rust Agent (with `sudo` for pcap).
    3.  Verify that the Go Manager's console successfully prints out traffic captured by the Rust Agent in real-time.