"""Lab-only TCP connect scan of a device YOU OWN. Creates SYN traffic to capture in Wireshark."""
import ipaddress
import socket
import sys

target = sys.argv[1]
start = int(sys.argv[2]) if len(sys.argv) > 2 else 1
end = int(sys.argv[3]) if len(sys.argv) > 3 else 200

if not ipaddress.ip_address(target).is_private:
    sys.exit("Refusing: target must be a private (home or lab) IP address.")

open_ports = []
for port in range(start, end + 1):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.3)
    if s.connect_ex((target, port)) == 0:
        open_ports.append(port)
    s.close()
print(f"Scanned ports {start}-{end} on {target}. Open: {open_ports}")