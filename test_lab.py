from scapy.all import IP, TCP, UDP, DNS, DNSQR, wrpcap
from netlab.analyzer import analyze, save_report
from netlab.diagnostics import http_check
import pytest


def test_pcap_analysis(tmp_path):
    path = tmp_path / 'test.pcap'
    packets = [IP(src='192.0.2.10', dst='198.51.100.20')/TCP(sport=45000, dport=443, flags='S'),
               IP(src='192.0.2.10', dst='198.51.100.53')/UDP(sport=52000, dport=53)/DNS(rd=1, qd=DNSQR(qname='example.org'))]
    wrpcap(str(path), packets)
    result = analyze(path)
    assert result['statistics']['packets'] == 2
    assert result['statistics']['tcp'] == 1
    assert result['dns_queries']['example.org'] == 1
    assert len(result['flows']) == 2
    assert save_report(result, tmp_path / 'report.json').exists()


def test_invalid_url():
    with pytest.raises(ValueError):
        http_check('ftp://example.org')


def test_missing_capture(tmp_path):
    with pytest.raises(FileNotFoundError):
        analyze(tmp_path / 'missing.pcap')
