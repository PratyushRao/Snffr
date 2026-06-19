# snffr
### **High-Performance Distributed IDS & Autonomous Response System**

`snffr` is a distributed security tool designed to sniff network traffic at the edge, analyze it centrally, and respond to threats automatically.

## Quick Start
1. **Prerequisites:** Linux (for libpcap), Docker, and Docker Compose.
2. **Build and Run:**
   ```bash
   docker-compose up --build
   ```

# Response Mechanism
    - P Dropping: Immediate block via iptables.
    - Rate Limiting: Reducing the allowed bandwidth for suspicious nodes.
    - Connection Killing: Terminating specific TCP sessions.

# NOTE
This project is currently in very early development.

## Future Roadmap
   - TUI Dashboard
   - AI Driven Threat Detection
   - Configurable Rule Engine