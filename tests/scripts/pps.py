import socket, time
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
payload = b"X" * 64
target = ("127.0.0.1", 9999)
COUNT = 50000

print(f"[*] Blasting {COUNT} packets to {target[0]}:{target[1]}...")
start = time.time()
for _ in range(COUNT):
    sock.sendto(payload, target)
duration = time.time() - start

pps = COUNT / duration
mbps = (COUNT * 64 * 8) / (duration * 1e6)
print(f"[+] Done in {duration:.3f}s | Throughput: {pps:,.2f} packets/sec ({mbps:.2f} Mbps)")