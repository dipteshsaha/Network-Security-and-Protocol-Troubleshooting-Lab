import argparse
import json
from .analyzer import analyze, save_report
from .diagnostics import dns_lookup, tcp_connect, tls_inspect, http_check


def main():
    parser = argparse.ArgumentParser(description='Network Security & Protocol Troubleshooting Lab')
    sub = parser.add_subparsers(dest='command', required=True)
    pcap = sub.add_parser('pcap', help='Analyze an offline packet capture')
    pcap.add_argument('file')
    pcap.add_argument('--output', default='reports/pcap-report.json')
    dns = sub.add_parser('dns', help='Resolve a hostname')
    dns.add_argument('host')
    tcp = sub.add_parser('tcp', help='Test a TCP connection')
    tcp.add_argument('host')
    tcp.add_argument('--port', type=int, default=443)
    tls = sub.add_parser('tls', help='Inspect TLS handshake and validated certificate')
    tls.add_argument('host')
    tls.add_argument('--port', type=int, default=443)
    http = sub.add_parser('http', help='Fetch HTTP status and timing')
    http.add_argument('url')
    args = parser.parse_args()
    if args.command == 'pcap':
        result = analyze(args.file)
        save_report(result, args.output)
        print(f'Report written to {args.output}')
    elif args.command == 'dns':
        result = dns_lookup(args.host)
    elif args.command == 'tcp':
        result = tcp_connect(args.host, args.port)
    elif args.command == 'tls':
        result = tls_inspect(args.host, args.port)
    else:
        result = http_check(args.url)
    if args.command != 'pcap':
        print(json.dumps(result, indent=2))

if __name__ == '__main__':
    main()
