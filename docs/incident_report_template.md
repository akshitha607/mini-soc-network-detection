# Incident Report: <title>

**Report date:** <date>   **Analyst:** <your name>   **Severity:** <Low/Medium/High/Critical>
**Status:** <Open/Contained/Closed>

## 1. Executive summary
Two or three sentences: what happened, what was affected, current status, recommended action.

## 2. Detection
- **How detected:** (Python detector name, Splunk alert name, analyst hunt)
- **First alert:** <timestamp UTC>
- **Alert details:** paste the JSON line from `alerts.jsonl` or the Splunk event

## 3. Timeline (UTC)
| Time | Event | Source |
|---|---|---|
| | Recon: SYN scan of victim begins | Wireshark / port_scan alert |
| | SSH brute force starts | brute_force alert |
| | Beaconing to external host | beaconing alert |

## 4. Technical analysis
- Packet-level evidence (Wireshark screenshots, display filters used)
- Splunk searches and results that confirm the activity
- Affected assets, accounts and data

## 5. MITRE ATT&CK mapping
| Tactic | Technique | Evidence |
|---|---|---|
| Discovery | T1046 Network Service Discovery | |
| Credential Access | T1110 Brute Force | |
| Command and Control | T1071 Application Layer Protocol | |

## 6. Indicators of compromise
| Type | Value | Context |
|---|---|---|
| IP | | |
| Domain | | |

## 7. Root cause
Why was this possible (exposed service, weak password, no rate limiting)?

## 8. Containment, eradication, recovery
Actions taken and still needed.

## 9. Recommendations
- Detection tuning (thresholds, false positives seen)
- Hardening (key-only SSH, fail2ban, network segmentation, egress filtering)

## 10. Lessons learned
