# Detection tuning log

Recruiters like seeing that you measured and tuned instead of guessing thresholds. Fill this in as you
run the detectors against real lab captures and benign baseline traffic (a few hours of normal browsing).

| Detector | Parameter | Default | Tried | True positives | False positives | Decision |
|---|---|---|---|---|---|---|
| port_scan | min_targets (60 s window) | 20 | 10 / 20 / 50 | | | |
| brute_force | min_attempts (60 s window) | 10 | 5 / 10 / 20 | | | |
| beaconing | max_cv | 0.15 | 0.05 / 0.15 / 0.3 | | | |
| beaconing | min_interval | 2 s | 1 / 2 / 5 | | | |
| dns_tunnel | entropy_threshold | 3.5 | 3.0 / 3.5 / 4.0 | | | |

## Known false-positive sources to investigate
- Software updaters, NTP, and monitoring agents produce very regular connections (beacon FPs): consider an allowlist.
- CDNs and long cloud hostnames can trip DNS length rules: consider a base-domain allowlist.
- Vulnerability scanners and load balancers look like port scans: allowlist known scanner IPs.

## Limits of this approach
Rule thresholds are easy to evade (slow scans, jittered beacons). Next step: compare against an
Isolation Forest on flow features and report precision/recall on CIC-IDS2017.
