# Network Security and Protocol Troubleshooting Lab

A Python portfolio lab for **offline packet-capture analysis** and **authorized DNS, TCP, TLS, and HTTP diagnostics**. Built to practice the protocol investigation skills relevant to network security and security architecture.

## Features
- Offline PCAP parsing with Scapy: IPv4/IPv6, TCP, UDP, ICMP, DNS
- Directional flow summaries, TCP SYN/SYN-ACK/RST/FIN counts
- DNS query frequency and response-code breakdown
- Heuristic flags for unusually high SYN counts and repeated TCP resets
- DNS hostname resolution, TCP connectivity, TLS certificate and cipher inspection, HTTP status and timing
- Machine-readable JSON reports, unit tests, and GitHub Actions CI

## Setup
Requires Python 3.10+.

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pytest -q
```

## Offline packet analysis
Use a capture you own or have explicit authorization to analyze:

```bash
python -m netlab.cli pcap /path/to/authorized-capture.pcap --output reports/analysis.json
```

## Protocol diagnostics
Only test endpoints you own or are authorized to assess:

```bash
python -m netlab.cli dns example.org
python -m netlab.cli tcp example.org --port 443
python -m netlab.cli tls example.org --port 443
python -m netlab.cli http https://example.org
```

## Investigation workflow
1. Establish DNS resolution and compare expected records.
2. Test TCP port connectivity; distinguish refusal from timeout.
3. Validate TLS handshake, certificate chain, hostname and negotiated protocol.
4. Inspect HTTP status codes, headers and response timing.
5. Review an authorized packet capture to correlate transport and DNS observations.
6. Document findings, limitations, and recommended next steps.

## Important limitations
- High SYN counts are a **heuristic**, not proof of a SYN flood or DDoS attack.
- This starter does not reconstruct complete TCP sessions, detect retransmissions, or decode encrypted HTTP content.
- DNS analysis handles common single-question messages; advanced EDNS and tunneled traffic are outside scope.
- TLS validation uses the operating system trust store and checks the requested hostname.
- Do not upload real captures containing sensitive traffic or credentials to public GitHub repositories.
- This tool is not a vulnerability scanner, exploit framework, or attack generator.

## Resume description
**Network Security and Protocol Troubleshooting Lab** — Developed a Python/Scapy-based troubleshooting toolkit to analyze PCAP traffic, summarize TCP and DNS behavior, flag suspicious traffic patterns, and validate DNS, TCP, TLS, and HTTP connectivity; added JSON reporting and automated tests.
