#!/usr/bin/env python3
import socket
import time
import argparse
import subprocess

def send_signature(target_ip, port=8080):
    print(f"[*] Simulating Malicious Payload signature attack on {target_ip}:{port}...")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2.0)
        s.connect((target_ip, port))
        s.sendall(b"GET /?query=ATTACK_SIGNATURE HTTP/1.1\r\nHost: target\r\n\r\n")
        print("[+] Sent payload containing: ATTACK_SIGNATURE")
        s.close()
    except Exception as e:
        print(f"[-] Connection failed (this is expected if port {port} is closed, but raw packet was transmitted to agent): {e}")

def simulate_ssh_bruteforce(target_ip):
    print(f"[*] Simulating SSH Bruteforce on {target_ip}:22...")
    for i in range(6):
        try:
            print(f"  [Attempt {i+1}/6] Connecting...")
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            s.connect((target_ip, 22))
            s.close()
        except Exception:
            # We expect connection errors since port 22 might not be open, 
            # but the packets are still sent and captured by the agent.
            pass
        time.sleep(0.1)
    print("[+] SSH bruteforce simulation finished.")

def simulate_dns_flood(target_ip):
    print(f"[*] Simulating DNS query flood on {target_ip}:53...")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    for i in range(25):
        try:
            sock.sendto(b"\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03www\x06google\x03com\x00\x00\x01\x00\x01", (target_ip, 53))
        except Exception as e:
            print(f"[-] Error sending packet: {e}")
            break
        time.sleep(0.05)
    print("[+] DNS simulation finished.")

def simulate_ping_flood(target_ip):
    print(f"[*] Simulating ICMP (ping) flood on {target_ip} using system ping...")
    # Trigger 12 ping packets quickly to breach the 10 pkts in 5s threshold
    for i in range(12):
        try:
            subprocess.Popen(["ping", "-c", "1", "-W", "1", target_ip], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            time.sleep(0.1)
        except Exception as e:
            print(f"[-] Error spawning ping: {e}")
            break
    print("[+] ICMP flood simulation finished.")

def main():
    parser = argparse.ArgumentParser(description="Snffr Attack & Incident Simulator")
    parser.add_argument("target", help="Target IP address (the IP of the machine running Snffr agent)")
    parser.add_argument("--type", choices=["signature", "ssh", "dns", "ping", "all"], default="all",
                        help="Type of attack simulation to run")
    parser.add_argument("--port", type=int, default=8080, help="Port to send the payload signature to")
    
    args = parser.parse_args()
    
    if args.type == "signature" or args.type == "all":
        send_signature(args.target, args.port)
        time.sleep(2)
        
    if args.type == "ssh" or args.type == "all":
        simulate_ssh_bruteforce(args.target)
        time.sleep(2)
        
    if args.type == "dns" or args.type == "all":
        simulate_dns_flood(args.target)
        time.sleep(2)
        
    if args.type == "ping" or args.type == "all":
        simulate_ping_flood(args.target)

if __name__ == "__main__":
    main()
