#!/usr/bin/env python3
import socket
import time
import argparse
import subprocess

class MetricsTracker:
    def __init__(self, target_ip):
        self.target_ip = target_ip
        self.start_time = time.time()
        self.attacks = []
        self.packets_transmitted = 0
        self.bytes_transmitted = 0
        self.tcp_success = 0
        self.tcp_failed = 0

    def record_attack(self, name):
        self.attacks.append(name)

    def record_packet(self, count=1, bytes_count=0):
        self.packets_transmitted += count
        self.bytes_transmitted += bytes_count

    def record_tcp_attempt(self, success):
        if success:
            self.tcp_success += 1
        else:
            self.tcp_failed += 1

    def print_summary(self):
        duration = time.time() - self.start_time
        pps = self.packets_transmitted / duration if duration > 0 else 0
        bps = self.bytes_transmitted / duration if duration > 0 else 0
        
        print("\n" + "=" * 50)
        print("                 ATTACK SIMULATION METRICS")
        print("=" * 50)
        print(f"Target Host:                 {self.target_ip}")
        print(f"Attacks Simulated:           {', '.join(self.attacks)}")
        print(f"Total Packets Transmitted:   {self.packets_transmitted}")
        print(f"Total Bytes Transmitted:     {self.bytes_transmitted} bytes")
        print(f"Successful TCP Connections:  {self.tcp_success}")
        print(f"Failed TCP Connections:      {self.tcp_failed}")
        print(f"Total Execution Time:        {duration:.2f} seconds")
        print(f"Average Packet Rate:         {pps:.2f} packets/sec")
        print(f"Average Byte Rate:           {bps:.2f} bytes/sec")
        print("=" * 50 + "\n")

def send_signature(target_ip, port=8080, metrics=None):
    if metrics:
        metrics.record_attack("Signature Payload")
    print(f"[*] Simulating Malicious Payload signature attack on {target_ip}:{port}...")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2.0)
        s.connect((target_ip, port))
        payload = b"GET /?query=ATTACK_SIGNATURE HTTP/1.1\r\nHost: target\r\n\r\n"
        s.sendall(payload)
        print("[+] Sent payload containing: ATTACK_SIGNATURE")
        s.close()
        if metrics:
            metrics.record_tcp_attempt(True)
            metrics.record_packet(1, len(payload))
    except Exception as e:
        print(f"[-] Connection failed (this is expected if port {port} is closed, but raw packet was transmitted to agent): {e}")
        if metrics:
            metrics.record_tcp_attempt(False)
            metrics.record_packet(1, 0)

def simulate_ssh_bruteforce(target_ip, metrics=None):
    if metrics:
        metrics.record_attack("SSH Bruteforce")
    print(f"[*] Simulating SSH Bruteforce on {target_ip}:22...")
    for i in range(6):
        try:
            print(f"  [Attempt {i+1}/6] Connecting...")
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            s.connect((target_ip, 22))
            s.close()
            if metrics:
                metrics.record_tcp_attempt(True)
                metrics.record_packet(1, 0)
        except Exception:
            # We expect connection errors since port 22 might not be open, 
            # but the packets are still sent and captured by the agent.
            if metrics:
                metrics.record_tcp_attempt(False)
                metrics.record_packet(1, 0)
            pass
        time.sleep(0.1)
    print("[+] SSH bruteforce simulation finished.")

def simulate_dns_flood(target_ip, metrics=None):
    if metrics:
        metrics.record_attack("DNS Query Flood")
    print(f"[*] Simulating DNS query flood on {target_ip}:53...")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    payload = b"\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03www\x06google\x03com\x00\x00\x01\x00\x01"
    payload_len = len(payload)
    packets_sent = 0
    for i in range(25):
        try:
            sock.sendto(payload, (target_ip, 53))
            packets_sent += 1
        except Exception as e:
            print(f"[-] Error sending packet: {e}")
            break
        time.sleep(0.05)
    
    if metrics and packets_sent > 0:
        metrics.record_packet(packets_sent, packets_sent * payload_len)
    print("[+] DNS simulation finished.")

def simulate_ping_flood(target_ip, metrics=None):
    if metrics:
        metrics.record_attack("ICMP Flood")
    print(f"[*] Simulating ICMP (ping) flood on {target_ip} using system ping...")
    # Trigger 12 ping packets quickly to breach the 10 pkts in 5s threshold
    pings_sent = 0
    for i in range(12):
        try:
            subprocess.Popen(["ping", "-c", "1", "-W", "1", target_ip], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            pings_sent += 1
            time.sleep(0.1)
        except Exception as e:
            print(f"[-] Error spawning ping: {e}")
            break

    if metrics and pings_sent > 0:
        metrics.record_packet(pings_sent, pings_sent * 64)
    print("[+] ICMP flood simulation finished.")

def main():
    parser = argparse.ArgumentParser(description="Snffr Attack & Incident Simulator")
    parser.add_argument("target", help="Target IP address (the IP of the machine running Snffr agent)")
    parser.add_argument("--type", choices=["signature", "ssh", "dns", "ping", "all"], default="all",
                        help="Type of attack simulation to run")
    parser.add_argument("--port", type=int, default=8080, help="Port to send the payload signature to")
    
    args = parser.parse_args()
    
    metrics = MetricsTracker(args.target)
    
    if args.type == "signature" or args.type == "all":
        send_signature(args.target, args.port, metrics)
        time.sleep(2)
        
    if args.type == "ssh" or args.type == "all":
        simulate_ssh_bruteforce(args.target, metrics)
        time.sleep(2)
        
    if args.type == "dns" or args.type == "all":
        simulate_dns_flood(args.target, metrics)
        time.sleep(2)
        
    if args.type == "ping" or args.type == "all":
        simulate_ping_flood(args.target, metrics)

    metrics.print_summary()

if __name__ == "__main__":
    main()
