from soc_pipeline.detectors import (
    detect_beaconing,
    detect_brute_force,
    detect_dns_tunnel,
    detect_port_scan,
    shannon_entropy,
)


def syn(src, dst, dport, ts):
    return {"ts": ts, "src": src, "dst": dst, "proto": "tcp", "sport": 40000,
            "dport": dport, "flags": "S", "length": 54, "dns_qname": None}


def dns(src, qname, ts):
    return {"ts": ts, "src": src, "dst": "10.0.0.1", "proto": "udp", "sport": 5353,
            "dport": 53, "flags": "", "length": 80, "dns_qname": qname}


def test_port_scan_detected():
    recs = [syn("1.1.1.1", "10.0.0.5", p, i * 0.1) for i, p in enumerate(range(1, 41))]
    alerts = detect_port_scan(recs)
    assert len(alerts) == 1 and alerts[0].mitre_technique == "T1046"


def test_port_scan_ignores_normal_client():
    recs = [syn("1.1.1.1", "10.0.0.5", 443, i * 5) for i in range(30)]  # same port repeatedly
    assert detect_port_scan(recs) == []


def test_port_scan_outside_window_not_flagged():
    recs = [syn("1.1.1.1", "10.0.0.5", p, p * 10.0) for p in range(1, 30)]  # 10 s apart
    assert detect_port_scan(recs, window=60, min_targets=20) == []


def test_brute_force_detected():
    recs = [syn("1.1.1.1", "10.0.0.5", 22, i * 0.5) for i in range(15)]
    alerts = detect_brute_force(recs)
    assert len(alerts) == 1 and alerts[0].evidence["service"] == "ssh"


def test_brute_force_below_threshold():
    recs = [syn("1.1.1.1", "10.0.0.5", 22, i * 0.5) for i in range(5)]
    assert detect_brute_force(recs) == []


def test_beaconing_detected():
    recs = [syn("10.0.0.9", "203.0.113.5", 8080, i * 10.0) for i in range(12)]
    alerts = detect_beaconing(recs)
    assert len(alerts) == 1 and alerts[0].mitre_technique == "T1071"


def test_beaconing_ignores_random_intervals():
    times = [0, 3, 19, 22, 70, 71, 140, 190, 200, 340]
    recs = [syn("10.0.0.9", "203.0.113.5", 8080, t) for t in times]
    assert detect_beaconing(recs) == []


def test_beaconing_ignores_fast_bursts():
    recs = [syn("1.1.1.1", "10.0.0.5", 22, i * 0.2) for i in range(30)]
    assert detect_beaconing(recs) == []


def test_dns_tunnel_detected():
    recs = [dns("10.0.0.9", f"{'a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0'[i:]}xyz{i}.t.evil.example", i)
            for i in range(8)]
    alerts = detect_dns_tunnel(recs)
    assert len(alerts) == 1 and alerts[0].evidence["base_domain"] == "evil.example"


def test_dns_normal_names_ignored():
    recs = [dns("10.0.0.9", "www.example.com", i) for i in range(20)]
    assert detect_dns_tunnel(recs) == []


def test_entropy_ordering():
    assert shannon_entropy("aaaaaaaa") < shannon_entropy("a1b2c3d4")
