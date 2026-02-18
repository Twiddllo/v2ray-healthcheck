#!/usr/bin/env python3

import socket
import ssl
import struct
import time
from typing import Tuple

from .parser import ProxyConfig


class TCPPreChecker:
    def __init__(self, timeout: float = 5.0):
        self.timeout = timeout

    def test_config_tcp(self, proxy: ProxyConfig) -> Tuple[bool, str]:
        try:
            start_time = time.time()

            try:
                server_ip = socket.getaddrinfo(proxy.server, None, socket.AF_INET)[0][4][0]
            except Exception:
                return False, "DNS resolution failed"

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)

            try:
                sock.connect((server_ip, proxy.port))
            except socket.timeout:
                return False, "TCP timeout"
            except Exception as e:
                return False, f"TCP failed: {str(e)[:30]}"

            if proxy.tls or proxy.security in ['tls', 'xtls', 'reality']:
                try:
                    context = ssl.create_default_context()
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE

                    sni = proxy.sni or proxy.host or proxy.server
                    with context.wrap_socket(sock, server_hostname=sni) as ssock:
                        cipher = ssock.cipher()
                        if not cipher:
                            return False, "SSL handshake failed"

                        if proxy.protocol == 'trojan':
                            import hashlib
                            password_hash = hashlib.sha224(proxy.password.encode()).hexdigest() if proxy.password else ""
                            target = b"\x03\x0bwww.google.com\x01\xbb"
                            ssock.send(password_hash.encode() + b"\r\n" + target)
                        elif proxy.protocol == 'vless' and proxy.uuid:
                            try:
                                import uuid
                                uid = uuid.UUID(proxy.uuid).bytes
                                header = bytes([0]) + uid + bytes([0, 1])
                                header += bytes([3, 11]) + b"google.com" + struct.pack(">H", 80)
                                ssock.send(header)
                            except Exception:
                                pass

                        elapsed = (time.time() - start_time) * 1000
                        return True, f"SSL OK - {elapsed:.0f}ms"

                except Exception as e:
                    return False, f"SSL error: {str(e)[:30]}"
            else:
                sock.close()
                elapsed = (time.time() - start_time) * 1000
                return True, f"TCP OK - {elapsed:.0f}ms"

        except Exception as e:
            return False, str(e)[:40]
