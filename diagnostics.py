"""Safe client-side diagnostics for hosts the operator is authorized to test."""
import socket
import ssl
import time
from urllib.parse import urlsplit
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError


def dns_lookup(host):
    try:
        addresses = sorted({item[4][0] for item in socket.getaddrinfo(host, None)})
        return {'host': host, 'addresses': addresses, 'status': 'ok'}
    except socket.gaierror as exc:
        return {'host': host, 'status': 'error', 'error': str(exc)}


def tcp_connect(host, port=443, timeout=3):
    start = time.monotonic()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return {'host': host, 'port': port, 'status': 'connected',
                    'latency_ms': round((time.monotonic() - start) * 1000, 2)}
    except OSError as exc:
        return {'host': host, 'port': port, 'status': 'error', 'error': str(exc)}


def tls_inspect(host, port=443, timeout=3):
    context = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls:
                cert = tls.getpeercert()
                return {'host': host, 'status': 'ok', 'tls_version': tls.version(),
                        'cipher': tls.cipher()[0], 'certificate_expiry': cert.get('notAfter'),
                        'certificate_subject': cert.get('subject')}
    except (OSError, ssl.SSLError) as exc:
        return {'host': host, 'status': 'error', 'error': str(exc)}


def http_check(url, timeout=5):
    parsed = urlsplit(url)
    if parsed.scheme not in ('http', 'https') or not parsed.hostname:
        raise ValueError('URL must use http:// or https:// and contain a hostname')
    req = Request(url, headers={'User-Agent': 'AuthorizedNetworkLab/1.0'})
    start = time.monotonic()
    try:
        with urlopen(req, timeout=timeout) as response:
            return {'url': url, 'status_code': response.status,
                    'latency_ms': round((time.monotonic() - start) * 1000, 2),
                    'server': response.headers.get('Server')}
    except HTTPError as exc:
        return {'url': url, 'status_code': exc.code, 'error': str(exc)}
    except URLError as exc:
        return {'url': url, 'status': 'error', 'error': str(exc)}
