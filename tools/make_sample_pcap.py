"""Generate a synthetic pcap so the pipeline can be demoed and tested without a lab.

Nothing is sent on the network: packets are crafted in memory and written to a file
with fabricated timestamps. It mixes benign background traffic with four attack
patterns the detectors look for. Replace it with real captures from your own lab VMs
(see docs/lab_setup.md) for the portfolio version.

    python tools/make_sample_pcap.py samples/lab_attacks.pcap
"""
from __future__ import annotations

import random
import string
import sys

from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether
from scapy.utils import wrpcap

random.seed(1337)

ATTACKER = "192.168.56.101"   # Kali
VICTIM = "192.168.56.102"     # Ubuntu / Metasploitable
WEB = "192.168.56.103"        # DVWA
CLIENT = "192.168.56.50"      # benign workstation
RESOLVER = "192.168.56.1"
T0 = 1_760_000_000.0


def tcp(src, dst, sport, dport, flags, ts):
    p = Ether() / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags=flags)
    p.time = ts
    return p


def dns_query(src, qname, ts):
    p = Ether() / IP(src=src, dst=RESOLVER) / UDP(sport=random.randint(30000, 60000), dport=53) / DNS(
        rd=1, qd=DNSQR(qname=qname)
    )
    p.time = ts
    return p


def benign(pkts):
    # Normal browsing + DNS
    for i in range(60):
        ts = T0 + i * random.uniform(1, 6)
        pkts.append(tcp(CLIENT, WEB, 40000 + i, 443, "S", ts))
        pkts.append(tcp(WEB, CLIENT, 443, 40000 + i, "SA", ts + 0.01))
        pkts.append(tcp(CLIENT, WEB, 40000 + i, 443, "A", ts + 0.02))
    for i, name in enumerate(["www.example.com", "mail.example.com", "cdn.example.com", "api.example.com"] * 3):
        pkts.append(dns_query(CLIENT, name, T0 + 5 + i * 11))


def port_scan(pkts):
    # Nmap-style SYN scan of 150 ports, ~50 ms apart
    for i, port in enumerate(random.sample(range(1, 1024), 150)):
        pkts.append(tcp(ATTACKER, VICTIM, 51000, port, "S", T0 + 60 + i * 0.05))


def brute_force(pkts):
    # Hydra-like SSH login attempts, ~0.3 s apart
    for i in range(40):
        ts = T0 + 120 + i * 0.3
        pkts.append(tcp(ATTACKER, VICTIM, 52000 + i, 22, "S", ts))
        pkts.append(tcp(VICTIM, ATTACKER, 22, 52000 + i, "SA", ts + 0.005))


def beacon(pkts):
    # Compromised host phones home every 10 s with ~3% jitter
    c2 = "203.0.113.50"  # TEST-NET-3 documentation address
    ts = T0 + 30
    for i in range(20):
        pkts.append(tcp(VICTIM, c2, 45000 + i, 8080, "S", ts))
        ts += 10 * random.uniform(0.97, 1.03)  # jitter each interval, not the running total


def dns_tunnel(pkts):
    # Base32-ish encoded chunks as subdomains of a made-up C2 domain
    alphabet = string.ascii_lowercase + string.digits
    for i in range(15):
        chunk = "".join(random.choices(alphabet, k=48))
        pkts.append(dns_query(VICTIM, f"{chunk}.t.evil-c2.example", T0 + 200 + i * 1.5))


def main(out: str) -> None:
    pkts: list = []
    benign(pkts)
    port_scan(pkts)
    brute_force(pkts)
    beacon(pkts)
    dns_tunnel(pkts)
    pkts.sort(key=lambda p: p.time)
    wrpcap(out, pkts)
    print(f"wrote {len(pkts)} packets to {out}")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "samples/lab_attacks.pcap")
