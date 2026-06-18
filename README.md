# snffr
### **High-Performance Distributed IDS & Autonomous Response System**

`snffr` is a distributed security tool designed to sniff network traffic at the edge, analyze it centrally, and respond to threats automatically.

## The Stack
- **Agents (Rust):** Low-level packet capture using `libpcap`. Maximum speed, zero memory leaks.
- **Manager (Go):** High-concurrency central analyzer handling gRPC streams from agents.
- **Dashboard (React + TS):** Real-time monitoring and command center via WebSockets.
- **Communication:** gRPC for Agent-to-Manager; WebSockets for Manager-to-Dashboard.

## How it Works
1. **Sniff:** Rust agents capture packet headers using promiscuous mode.
2. **Report:** Metadata (Src IP, Dst IP, Port, Protocol, Flags) is sent to the Manager via gRPC.
3. **Analyze:** The Manager runs a **Signature Engine** to detect known attack patterns (e.g., Nmap scans).
4. **Respond:** If a rule is triggered, the Manager sends a `BLOCK` signal. The Agent then executes a local `iptables` command to drop all future traffic from that IP.
5. **Visualize:** All activity is streamed live to the ReactTS dashboard for the admin.

## Quick Start
1. **Prerequisites:** Linux (for libpcap), Docker, and Docker Compose.
2. **Build and Run:**
   ```bash
   docker-compose up --build
   ```
3. View Dashboard: Navigate to http://localhost:3000 to see live traffic from your containerized agents.

# Response Mechanism
    - P Dropping: Immediate block via iptables.
    - Rate Limiting: Reducing the allowed bandwidth for suspicious nodes.
    - Connection Killing: Terminating specific TCP sessions.