# Wireshark: what each attack looks like

For your portfolio, capture each attack from your own lab, then screenshot these views
into `docs/screenshots/` and reference them in the incident report.

| Attack | Display filter | What to point out | Statistics view |
|---|---|---|---|
| SYN port scan | `tcp.flags.syn==1 && tcp.flags.ack==0` | One source, hundreds of destination ports, tiny inter-packet gaps, mostly answered by `RST,ACK` | Statistics > Conversations > TCP |
| Open vs closed ports | `tcp.flags.syn==1 && tcp.flags.ack==1` | `SYN,ACK` replies reveal the open ports | Statistics > Endpoints |
| SSH brute force | `tcp.dstport==22 && tcp.flags.syn==1` | Many short-lived connections from one IP to port 22 | Statistics > Conversations |
| FTP brute force | `ftp.request.command == "PASS"` | Repeated `USER`/`PASS` pairs, `530 Login incorrect` replies (`ftp.response.code==530`) | Follow TCP Stream |
| ARP spoofing | `arp.duplicate-address-detected \|\| arp.opcode==2` | Same IP claimed by two MACs, unsolicited ARP replies | Expert Info |
| DNS tunneling | `dns && frame.len > 100` or `dns.qry.name.len > 40` | Long random-looking subdomains of one domain, many TXT/NULL queries | Statistics > DNS |
| C2 beaconing | `ip.dst==<C2 IP> && tcp.flags.syn==1` | Evenly spaced connections; add `frame.time_delta_displayed` as a column | Statistics > I/O Graph |
| SQL injection | `http.request.uri contains "UNION" \|\| http.request.uri contains "%27"` | Payloads in query strings against DVWA | Follow HTTP Stream |
| Cleartext credentials | `http.authorization \|\| ftp.request.command=="PASS" \|\| telnet` | Why plaintext protocols are a risk | Follow TCP Stream |

## Tips
- Save each attack as its own file (`portscan.pcap`, `ssh_bruteforce.pcap`, ...) with `tshark -r big.pcap -w small.pcap -Y "<filter>"`.
- Right-click a filter result > *Apply as Column* for `frame.time_delta_displayed`; sorting by it exposes beacon regularity.
- `tshark -r portscan.pcap -q -z conv,tcp` gives conversation stats you can paste into the report.
- Cross-check: run `python -m soc_pipeline analyze portscan.pcap` and confirm the Python alert matches what you see in Wireshark.
