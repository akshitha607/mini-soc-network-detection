"""Rule-based network detectors.

Every detector takes an iterable of packet records (see parser.py) and returns
a list of Alert objects. Thresholds are parameters so they can be tuned and the
tuning documented (false-positive vs. detection tradeoffs).
"""
from __future__ import annotations

import math
import statistics
from collections import Counter, defaultdict, deque
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Tuple

Record = Dict[str, Any]

BRUTE_FORCE_PORTS = {21: "ftp", 22: "ssh", 23: "telnet", 3389: "rdp", 5900: "vnc"}


@dataclass
class Alert:
    alert_type: str
    severity: str
    src_ip: str
    dst_ip: str
    mitre_technique: str
    mitre_name: str
    description: str
    first_seen: float
    last_seen: float
    evidence: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["timestamp"] = datetime.fromtimestamp(self.first_seen, tz=timezone.utc).isoformat()
        return d


def _syn_only(r: Record) -> bool:
    """Pure SYN = a new TCP connection attempt (no ACK)."""
    return r["proto"] == "tcp" and r["flags"] == "S"


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


# --------------------------------------------------------------------------
# 1. Port scan  (MITRE T1046 Network Service Discovery)
# --------------------------------------------------------------------------
def detect_port_scan(
    records: Iterable[Record], window: float = 60.0, min_targets: int = 20
) -> List[Alert]:
    """One source touching many distinct (dst, dport) pairs with SYNs in a window."""
    by_src: Dict[str, List[Record]] = defaultdict(list)
    for r in records:
        if _syn_only(r):
            by_src[r["src"]].append(r)

    alerts: List[Alert] = []
    for src, syns in by_src.items():
        syns.sort(key=lambda r: r["ts"])
        win: deque = deque()
        counts: Counter = Counter()
        best: Tuple[int, float, float] = (0, 0.0, 0.0)
        for r in syns:
            win.append(r)
            counts[(r["dst"], r["dport"])] += 1
            while r["ts"] - win[0]["ts"] > window:
                old = win.popleft()
                key = (old["dst"], old["dport"])
                counts[key] -= 1
                if counts[key] == 0:
                    del counts[key]
            if len(counts) > best[0]:
                best = (len(counts), win[0]["ts"], r["ts"])
        if best[0] >= min_targets:
            targets = {r["dst"] for r in syns if best[1] <= r["ts"] <= best[2]}
            alerts.append(
                Alert(
                    alert_type="port_scan",
                    severity="medium",
                    src_ip=src,
                    dst_ip=",".join(sorted(targets)[:5]),
                    mitre_technique="T1046",
                    mitre_name="Network Service Discovery",
                    description=f"{src} sent SYNs to {best[0]} distinct host:port pairs "
                    f"within {window:.0f}s",
                    first_seen=best[1],
                    last_seen=best[2],
                    evidence={"unique_targets": best[0], "window_s": window,
                              "threshold": min_targets},
                )
            )
    return alerts


# --------------------------------------------------------------------------
# 2. Brute force  (MITRE T1110 Brute Force)
# --------------------------------------------------------------------------
def detect_brute_force(
    records: Iterable[Record], window: float = 60.0, min_attempts: int = 10
) -> List[Alert]:
    """Many new connections from one source to one auth service (ssh/ftp/rdp...)."""
    groups: Dict[Tuple[str, str, int], List[float]] = defaultdict(list)
    for r in records:
        if _syn_only(r) and r["dport"] in BRUTE_FORCE_PORTS:
            groups[(r["src"], r["dst"], r["dport"])].append(r["ts"])

    alerts: List[Alert] = []
    for (src, dst, port), times in groups.items():
        times.sort()
        lo = 0
        best = (0, 0.0, 0.0)
        for hi, t in enumerate(times):
            while t - times[lo] > window:
                lo += 1
            n = hi - lo + 1
            if n > best[0]:
                best = (n, times[lo], t)
        if best[0] >= min_attempts:
            svc = BRUTE_FORCE_PORTS[port]
            alerts.append(
                Alert(
                    alert_type="brute_force",
                    severity="high",
                    src_ip=src,
                    dst_ip=dst,
                    mitre_technique="T1110",
                    mitre_name="Brute Force",
                    description=f"{best[0]} {svc.upper()} connection attempts from {src} "
                    f"to {dst}:{port} within {window:.0f}s",
                    first_seen=best[1],
                    last_seen=best[2],
                    evidence={"service": svc, "dport": port, "attempts": best[0],
                              "window_s": window, "threshold": min_attempts},
                )
            )
    return alerts


# --------------------------------------------------------------------------
# 3. Beaconing / C2  (MITRE T1071 Application Layer Protocol)
# --------------------------------------------------------------------------
def detect_beaconing(
    records: Iterable[Record],
    min_events: int = 8,
    max_cv: float = 0.15,
    min_interval: float = 2.0,
) -> List[Alert]:
    """Connections to the same dst:port at near-constant intervals.

    Uses the coefficient of variation (stdev / mean) of inter-arrival times.
    `min_interval` excludes fast bursts (scans, brute force) from being called beacons.
    """
    groups: Dict[Tuple[str, str, int], List[float]] = defaultdict(list)
    for r in records:
        if _syn_only(r):
            groups[(r["src"], r["dst"], r["dport"])].append(r["ts"])

    alerts: List[Alert] = []
    for (src, dst, port), times in groups.items():
        if len(times) < min_events:
            continue
        times.sort()
        deltas = [b - a for a, b in zip(times, times[1:])]
        mean = statistics.fmean(deltas)
        if mean < min_interval:
            continue
        cv = statistics.pstdev(deltas) / mean if mean else 1.0
        if cv <= max_cv:
            alerts.append(
                Alert(
                    alert_type="beaconing",
                    severity="high",
                    src_ip=src,
                    dst_ip=dst,
                    mitre_technique="T1071",
                    mitre_name="Application Layer Protocol",
                    description=f"{src} connects to {dst}:{port} every ~{mean:.1f}s "
                    f"(CV={cv:.3f}, {len(times)} connections): possible C2 beacon",
                    first_seen=times[0],
                    last_seen=times[-1],
                    evidence={"dport": port, "connections": len(times),
                              "mean_interval_s": round(mean, 2), "cv": round(cv, 4),
                              "max_cv": max_cv},
                )
            )
    return alerts


# --------------------------------------------------------------------------
# 4. DNS tunneling  (MITRE T1071.004 DNS)
# --------------------------------------------------------------------------
def _split_domain(qname: str) -> Tuple[str, str]:
    """Return (subdomain, base_domain). Naive last-two-labels split (fine for a lab)."""
    labels = qname.split(".")
    if len(labels) <= 2:
        return "", qname
    return ".".join(labels[:-2]), ".".join(labels[-2:])


def detect_dns_tunnel(
    records: Iterable[Record],
    min_queries: int = 5,
    long_len: int = 30,
    entropy_len: int = 20,
    entropy_threshold: float = 3.5,
) -> List[Alert]:
    """Long and/or high-entropy subdomains repeatedly queried under one base domain."""
    groups: Dict[Tuple[str, str], List[Tuple[float, str, float]]] = defaultdict(list)
    for r in records:
        q = r.get("dns_qname")
        if not q:
            continue
        sub, base = _split_domain(q)
        if not sub:
            continue
        ent = shannon_entropy(sub.replace(".", ""))
        suspicious = len(sub) >= long_len or (len(sub) >= entropy_len and ent >= entropy_threshold)
        if suspicious:
            groups[(r["src"], base)].append((r["ts"], r["dst"], ent))

    alerts: List[Alert] = []
    for (src, base), hits in groups.items():
        if len(hits) < min_queries:
            continue
        hits.sort()
        avg_ent = statistics.fmean(h[2] for h in hits)
        alerts.append(
            Alert(
                alert_type="dns_tunnel",
                severity="high",
                src_ip=src,
                dst_ip=hits[0][1],
                mitre_technique="T1071.004",
                mitre_name="Application Layer Protocol: DNS",
                description=f"{len(hits)} long/high-entropy DNS queries from {src} "
                f"under {base} (avg entropy {avg_ent:.2f}): possible DNS tunneling",
                first_seen=hits[0][0],
                last_seen=hits[-1][0],
                evidence={"base_domain": base, "suspicious_queries": len(hits),
                          "avg_entropy": round(avg_ent, 3), "threshold": min_queries},
            )
        )
    return alerts


def run_all(records: Iterable[Record]) -> List[Alert]:
    recs = list(records)  # pcaps in a lab are small; detectors need several passes
    alerts = (
        detect_port_scan(recs)
        + detect_brute_force(recs)
        + detect_beaconing(recs)
        + detect_dns_tunnel(recs)
    )
    return sorted(alerts, key=lambda a: a.first_seen)
