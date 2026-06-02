#!/usr/bin/env python3

import socket
import ssl
import time
from typing import List, Tuple

from .parser import ProxyConfig

_TLS_SECURITY = frozenset(('tls', 'xtls', 'reality'))


class TCPPreChecker:
    def __init__(self, timeout: float = 5.0):
        self.timeout = timeout

    def test_config_tcp(self, proxy: ProxyConfig) -> Tuple[bool, str]:
        start_time = time.perf_counter()
        errors: List[str] = []

        try:
            targets = self._resolve_targets(proxy.server, proxy.port)
            if not targets:
                return False, "DNS resolution failed"

            for family, sockaddr in targets:
                sock = socket.socket(family, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                try:
                    sock.connect(sockaddr)
                    if self._needs_tls(proxy):
                        return self._tls_handshake(sock, proxy, start_time)

                    sock.close()
                    elapsed = (time.perf_counter() - start_time) * 1000
                    return True, f"TCP OK - {elapsed:.0f}ms"
                except socket.timeout:
                    errors.append("timeout")
                    try:
                        sock.close()
                    except OSError:
                        pass
                except OSError as exc:
                    errors.append(str(exc))
                    try:
                        sock.close()
                    except OSError:
                        pass

            if any(err == "timeout" for err in errors):
                return False, "TCP timeout"
            if errors:
                return False, f"TCP failed: {errors[-1][:30]}"
            return False, "TCP failed"

        except Exception as exc:
            return False, str(exc)[:40]

    @staticmethod
    def _needs_tls(proxy: ProxyConfig) -> bool:
        if proxy.tls:
            return True
        security = (proxy.security or '').lower()
        return security in _TLS_SECURITY

    def _tls_handshake(self, sock: socket.socket, proxy: ProxyConfig, start_time: float) -> Tuple[bool, str]:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        sni = proxy.sni or proxy.host or proxy.server
        try:
            with context.wrap_socket(sock, server_hostname=sni) as ssock:
                if not ssock.cipher():
                    return False, "SSL handshake failed"
                elapsed = (time.perf_counter() - start_time) * 1000
                return True, f"SSL OK - {elapsed:.0f}ms"
        except Exception as exc:
            try:
                sock.close()
            except Exception:
                pass
            return False, f"SSL error: {str(exc)[:30]}"

    def _resolve_targets(self, host: str, port: int) -> List[Tuple[int, Tuple[str, int]]]:
        try:
            results = socket.getaddrinfo(
                host,
                port,
                type=socket.SOCK_STREAM,
            )
        except socket.gaierror:
            return []

        targets: List[Tuple[int, Tuple[str, int]]] = []
        for family, _, _, _, sockaddr in results:
            if family in (socket.AF_INET, socket.AF_INET6):
                targets.append((family, sockaddr))
        return targets
