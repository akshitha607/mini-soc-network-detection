"""Ship alerts to Splunk over the HTTP Event Collector (HEC)."""
from __future__ import annotations

import json
from typing import Any, Dict, Iterable, List

import requests


def build_payload(alerts: Iterable[Dict[str, Any]], index: str, sourcetype: str, source: str) -> List[str]:
    """One HEC envelope per alert. HEC accepts concatenated JSON objects in a single POST."""
    return [
        json.dumps(
            {
                "time": a["first_seen"],
                "host": a.get("src_ip", "mini-soc"),
                "source": source,
                "sourcetype": sourcetype,
                "index": index,
                "event": a,
            }
        )
        for a in alerts
    ]


def send_alerts(
    alerts: Iterable[Dict[str, Any]],
    url: str,
    token: str,
    index: str = "soc_lab",
    sourcetype: str = "soc:alert",
    source: str = "mini-soc",
    verify_tls: bool = False,
    batch_size: int = 50,
    timeout: float = 10.0,
) -> int:
    """POST alerts in batches. Returns the number of events accepted.

    `verify_tls` defaults to False because the lab Splunk uses a self-signed cert.
    Set SPLUNK_VERIFY_TLS=true (see cli.py) for any real deployment.
    """
    envelopes = build_payload(alerts, index, sourcetype, source)
    headers = {"Authorization": f"Splunk {token}"}
    sent = 0
    for i in range(0, len(envelopes), batch_size):
        chunk = envelopes[i : i + batch_size]
        resp = requests.post(
            url, data="\n".join(chunk), headers=headers, verify=verify_tls, timeout=timeout
        )
        resp.raise_for_status()
        sent += len(chunk)
    return sent
