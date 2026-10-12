"""Stream packets out of a pcap and reduce them to flat dict records.

Keeping the detectors working on plain dicts (not Scapy objects) makes them
fast, easy to unit-test, and independent of the capture library.
"""
from __future__ import annotations

from typing import Any, Dict, Iterator

from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, TCP, UDP
from scapy.utils import PcapReader

Record = Dict[str, Any]


def iter_records(pcap_path: str) -> Iterator[Record]:
    """Yield one record per IPv4 packet.

    Fields: ts, src, dst, proto, sport, dport, flags, length, dns_qname.
    """
    with PcapReader(pcap_path) as reader:
        for pkt in reader:
            if IP not in pkt:
                continue
            ip = pkt[IP]
            rec: Record = {
                "ts": float(pkt.time),
                "src": ip.src,
                "dst": ip.dst,
                "proto": "other",
                "sport": None,
                "dport": None,
                "flags": "",
                "length": len(pkt),
                "dns_qname": None,
            }
            if TCP in pkt:
                tcp = pkt[TCP]
                rec.update(
                    proto="tcp",
                    sport=int(tcp.sport),
                    dport=int(tcp.dport),
                    flags=str(tcp.flags),
                )
            elif UDP in pkt:
                udp = pkt[UDP]
                rec.update(proto="udp", sport=int(udp.sport), dport=int(udp.dport))
                if DNS in pkt and pkt[DNS].qr == 0 and pkt.haslayer(DNSQR):
                    qname = pkt[DNSQR].qname
                    if isinstance(qname, bytes):
                        qname = qname.decode("utf-8", errors="ignore")
                    rec["dns_qname"] = qname.rstrip(".").lower()
            yield rec
