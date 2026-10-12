"""Command line entry point:  python -m soc_pipeline analyze capture.pcap"""
from __future__ import annotations

import argparse
import json
import os
import sys

from .detectors import run_all
from .parser import iter_records
from .splunk_hec import send_alerts


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="soc_pipeline", description="Mini-SOC pcap analyzer")
    sub = p.add_subparsers(dest="cmd", required=True)

    a = sub.add_parser("analyze", help="run detectors on a pcap")
    a.add_argument("pcap")
    a.add_argument("--out", default="alerts.jsonl", help="write alerts as JSON lines")
    a.add_argument("--splunk", action="store_true",
                   help="also send to Splunk HEC (needs SPLUNK_HEC_URL and SPLUNK_HEC_TOKEN)")
    args = p.parse_args(argv)

    alerts = [x.to_dict() for x in run_all(iter_records(args.pcap))]

    with open(args.out, "w", encoding="utf-8") as fh:
        for al in alerts:
            fh.write(json.dumps(al) + "\n")

    print(f"{len(alerts)} alert(s) written to {args.out}")
    for al in alerts:
        print(f"  [{al['severity'].upper():6}] {al['alert_type']:12} {al['mitre_technique']:10} {al['description']}")

    if args.splunk:
        url = os.environ.get("SPLUNK_HEC_URL", "https://localhost:8088/services/collector/event")
        token = os.environ.get("SPLUNK_HEC_TOKEN")
        if not token:
            print("SPLUNK_HEC_TOKEN is not set", file=sys.stderr)
            return 2
        verify = os.environ.get("SPLUNK_VERIFY_TLS", "false").lower() == "true"
        n = send_alerts(alerts, url, token, verify_tls=verify)
        print(f"sent {n} event(s) to Splunk")
    return 0


if __name__ == "__main__":
    sys.exit(main())
