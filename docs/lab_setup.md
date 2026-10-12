# Lab setup (isolated, safe)

Only attack machines you own, inside an isolated network. Use a **host-only** or **internal** virtual
network so nothing reaches the internet or other people's systems.

## VMs (VirtualBox or VMware)
| Role | Suggested image | IP (example) |
|---|---|---|
| Attacker | Kali Linux | 192.168.56.101 |
| Victim | Ubuntu Server with `openssh-server`, or Metasploitable 2 | 192.168.56.102 |
| Web target | DVWA (Docker: `docker run -d -p 80:80 vulnerables/web-dvwa`) | 192.168.56.103 |
| Monitor | Your host or a 4th VM running Wireshark/tshark + this repo + Splunk | host-only gateway |

Capture on the host-only adapter (Wireshark: select the `vboxnet0`/`VMnet` interface), or on the victim with
`sudo tcpdump -i eth0 -w capture.pcap`.

## Attack scenarios to generate (one pcap each)
1. **Port scan:** `nmap -sS -p- 192.168.56.102`
2. **SSH brute force:** `hydra -l testuser -P small-wordlist.txt ssh://192.168.56.102` (use a short wordlist you create)
3. **DNS tunneling simulation:** a short Python script on the victim that queries long random subdomains of a domain you control or a `.example` name against a local resolver
4. **Beaconing simulation:** a loop on the victim: `while true; do curl -s http://192.168.56.101:8080/ping; sleep 10; done`
5. **SQL injection:** DVWA security level low, `sqlmap` or manual `' OR 1=1 -- ` payloads
6. **ARP spoofing:** `arpspoof` or `ettercap` between victim and gateway (host-only network only)

## Pipeline run
```bash
pip install -r requirements.txt
docker compose -f splunk/docker-compose.yml up -d     # wait ~2 min for Splunk
# In Splunk: Settings > Indexes > New Index "soc_lab"; confirm HEC token exists (Settings > Data inputs > HTTP Event Collector)
export SPLUNK_HEC_TOKEN=11111111-2222-3333-4444-555555555555
python -m soc_pipeline analyze captures/portscan.pcap --splunk
```
Then open Splunk, run the searches in `splunk/searches.spl`, and import `splunk/dashboard.xml`.
