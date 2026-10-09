"""Analyze authorized, offline PCAPs. No packets are transmitted."""
from collections import Counter, defaultdict
from pathlib import Path
import json
from scapy.all import PcapReader, IP, IPv6, TCP, UDP, DNS, DNSQR, ICMP


def analyze(path):
    path = Path(path)
    if not path.is_file():
        raise FileNotFoundError(path)
    stats = Counter()
    flows = defaultdict(lambda: {'packets': 0, 'bytes': 0, 'syn': 0, 'syn_ack': 0, 'rst': 0, 'fin': 0})
    dns_queries = Counter()
    dns_rcodes = Counter()
    alerts = []
    syn_sources = Counter()
    with PcapReader(str(path)) as reader:
        for pkt in reader:
            stats['packets'] += 1
            stats['bytes'] += len(pkt)
            if IP in pkt:
                src, dst = pkt[IP].src, pkt[IP].dst
                stats['ipv4'] += 1
            elif IPv6 in pkt:
                src, dst = pkt[IPv6].src, pkt[IPv6].dst
                stats['ipv6'] += 1
            else:
                stats['other_l2'] += 1
                continue
            if TCP in pkt:
                layer = pkt[TCP]
                proto = 'TCP'
                flags = int(layer.flags)
                stats['tcp'] += 1
                key = (src, layer.sport, dst, layer.dport, proto)
                flow = flows[key]
                flow['packets'] += 1
                flow['bytes'] += len(pkt)
                if flags & 0x02 and not flags & 0x10:
                    flow['syn'] += 1
                    syn_sources[src] += 1
                if flags & 0x12 == 0x12:
                    flow['syn_ack'] += 1
                if flags & 0x04:
                    flow['rst'] += 1
                if flags & 0x01:
                    flow['fin'] += 1
            elif UDP in pkt:
                layer = pkt[UDP]
                stats['udp'] += 1
                key = (src, layer.sport, dst, layer.dport, 'UDP')
                flows[key]['packets'] += 1
                flows[key]['bytes'] += len(pkt)
            elif ICMP in pkt:
                stats['icmp'] += 1
            if DNS in pkt:
                stats['dns'] += 1
                dns = pkt[DNS]
                if dns.qr == 0 and DNSQR in pkt:
                    qname = pkt[DNSQR].qname.decode('utf-8', errors='replace').rstrip('.')
                    dns_queries[qname] += 1
                elif dns.qr == 1:
                    dns_rcodes[str(dns.rcode)] += 1
    for source, count in syn_sources.items():
        if count >= 100:
            alerts.append({'type': 'high_syn_count', 'source': source, 'count': count,
                           'note': 'Heuristic only; investigate before labeling as attack'})
    for key, flow in flows.items():
        if flow['rst'] >= 10:
            alerts.append({'type': 'many_tcp_resets', 'flow': list(key), 'count': flow['rst']})
    return {
        'file': path.name,
        'statistics': dict(stats),
        'dns_queries': dict(dns_queries.most_common(20)),
        'dns_response_codes': dict(dns_rcodes),
        'flows': [{'source': k[0], 'sport': k[1], 'destination': k[2],
                   'dport': k[3], 'protocol': k[4], **v}
                  for k, v in sorted(flows.items(), key=lambda kv: kv[1]['packets'], reverse=True)],
        'alerts': alerts,
        'limitations': ['TCP retransmissions and handshake success are not inferred from packet counts.',
                        'Encrypted TLS payloads are not decrypted.',
                        'A single capture vantage point may not show both directions.']
    }


def save_report(report, destination):
    target = Path(destination)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(report, indent=2), encoding='utf-8')
    return target
