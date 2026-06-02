#!/usr/bin/env python3

import json
import os
import socket
import struct
import subprocess
import tempfile
import time
from typing import Tuple

from .parser import ProxyConfig


class XrayConfigBuilder:
    @staticmethod
    def _tls_settings(proxy: ProxyConfig) -> dict:
        return {
            "serverName": proxy.sni or proxy.host or proxy.server,
            "allowInsecure": True,
            "fingerprint": proxy.fp or "chrome",
        }

    @staticmethod
    def build_config(proxy: ProxyConfig, local_port: int = 10808) -> dict:
        inbound = {
            "listen": "127.0.0.1",
            "port": local_port,
            "protocol": "socks",
            "settings": {
                "auth": "noauth",
                "udp": True,
            },
            "sniffing": {
                "enabled": True,
                "destOverride": ["http", "tls"],
            },
        }

        outbound = XrayConfigBuilder._build_outbound(proxy)

        return {
            "log": {"loglevel": "error"},
            "inbounds": [inbound],
            "outbounds": [outbound],
        }

    @staticmethod
    def _build_outbound(proxy: ProxyConfig) -> dict:
        builders = {
            'vless': XrayConfigBuilder._build_vless_outbound,
            'vmess': XrayConfigBuilder._build_vmess_outbound,
            'ss': XrayConfigBuilder._build_ss_outbound,
            'trojan': XrayConfigBuilder._build_trojan_outbound,
        }
        builder = builders.get(proxy.protocol)
        if not builder:
            raise ValueError(f"Unsupported protocol: {proxy.protocol}")
        return builder(proxy)

    @staticmethod
    def _stream_settings(proxy: ProxyConfig) -> dict:
        network = proxy.network or "tcp"
        stream_settings = {"network": network}
        security = (proxy.security or '').lower()

        if proxy.tls or security in ('tls', 'xtls', 'reality'):
            tls_settings = XrayConfigBuilder._tls_settings(proxy)

            if security == 'reality' and proxy.pbk:
                tls_settings["publicKey"] = proxy.pbk
                if proxy.sid:
                    tls_settings["shortId"] = proxy.sid
                tls_settings["spiderX"] = proxy.path or "/"
                stream_settings["security"] = "reality"
                stream_settings["realitySettings"] = tls_settings
            else:
                stream_settings["security"] = "tls"
                stream_settings["tlsSettings"] = tls_settings

        if network == 'ws':
            stream_settings["wsSettings"] = {
                "path": proxy.path or "/",
                "headers": {"Host": proxy.host or proxy.server},
            }
        elif network == 'grpc':
            stream_settings["grpcSettings"] = {
                "serviceName": proxy.path or "",
                "multiMode": False,
            }
        elif network == 'h2':
            stream_settings["httpSettings"] = {
                "path": proxy.path or "/",
                "host": [proxy.host or proxy.server],
            }

        return stream_settings

    @staticmethod
    def _build_vless_outbound(proxy: ProxyConfig) -> dict:
        return {
            "protocol": "vless",
            "settings": {
                "vnext": [{
                    "address": proxy.server,
                    "port": proxy.port,
                    "users": [{
                        "id": proxy.uuid,
                        "encryption": "none",
                        "flow": proxy.flow or "",
                    }],
                }],
            },
            "streamSettings": XrayConfigBuilder._stream_settings(proxy),
            "tag": "proxy",
        }

    @staticmethod
    def _build_vmess_outbound(proxy: ProxyConfig) -> dict:
        return {
            "protocol": "vmess",
            "settings": {
                "vnext": [{
                    "address": proxy.server,
                    "port": proxy.port,
                    "users": [{
                        "id": proxy.uuid,
                        "alterId": proxy.alter_id or 0,
                        "security": "auto",
                    }],
                }],
            },
            "streamSettings": XrayConfigBuilder._stream_settings(proxy),
            "tag": "proxy",
        }

    @staticmethod
    def _build_ss_outbound(proxy: ProxyConfig) -> dict:
        return {
            "protocol": "shadowsocks",
            "settings": {
                "servers": [{
                    "address": proxy.server,
                    "port": proxy.port,
                    "method": proxy.method or "aes-256-gcm",
                    "password": proxy.password or "",
                }],
            },
            "tag": "proxy",
        }

    @staticmethod
    def _build_trojan_outbound(proxy: ProxyConfig) -> dict:
        stream_settings = XrayConfigBuilder._stream_settings(proxy)
        stream_settings["security"] = "tls"
        stream_settings["tlsSettings"] = XrayConfigBuilder._tls_settings(proxy)

        return {
            "protocol": "trojan",
            "settings": {
                "servers": [{
                    "address": proxy.server,
                    "port": proxy.port,
                    "password": proxy.password,
                }],
            },
            "streamSettings": stream_settings,
            "tag": "proxy",
        }


class XrayValidator:
    def __init__(self, xray_path: str = "xray", startup_delay: float = 0.6):
        self.xray_path = xray_path
        self.startup_delay = startup_delay
        self.timeout = 12
        self.startup_timeout = 5.0

    def test_config_with_xray(self, proxy: ProxyConfig) -> Tuple[bool, float]:
        process = None
        config_path = None

        try:
            local_port = self._find_free_port()
            config = XrayConfigBuilder.build_config(proxy, local_port)

            with tempfile.NamedTemporaryFile(
                mode='w',
                suffix='.json',
                delete=False,
            ) as handle:
                json.dump(config, handle)
                config_path = handle.name

            popen_kwargs = {
                'stdout': subprocess.DEVNULL,
                'stderr': subprocess.DEVNULL,
            }
            if os.name == 'nt':
                popen_kwargs['creationflags'] = subprocess.CREATE_NO_WINDOW

            process = subprocess.Popen(
                [self.xray_path, 'run', '-c', config_path],
                **popen_kwargs,
            )

            if not self._wait_for_socks_startup(process, local_port):
                return False, -1.0

            latency = self._test_through_proxy(local_port)
            return latency > 0, latency

        except Exception:
            return False, -1.0
        finally:
            if process is not None:
                process.terminate()
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill()
            if config_path:
                try:
                    os.unlink(config_path)
                except OSError:
                    pass

    def _find_free_port(self) -> int:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind(('127.0.0.1', 0))
            return sock.getsockname()[1]

    def _test_through_proxy(self, proxy_port: int) -> float:
        sock = None
        try:
            start_time = time.perf_counter()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect(('127.0.0.1', proxy_port))

            sock.sendall(b"\x05\x01\x00")
            response = self._recv_exact(sock, 2)
            if len(response) < 2 or response[0] != 0x05 or response[1] != 0x00:
                return -1.0

            destination = b"connectivitycheck.gstatic.com"
            request = (
                b"\x05\x01\x00\x03"
                + bytes([len(destination)])
                + destination
                + struct.pack('>H', 80)
            )
            sock.sendall(request)

            head = self._recv_exact(sock, 4)
            if len(head) < 4 or head[1] != 0x00:
                return -1.0
            atyp = head[3]
            if atyp == 0x01:
                _ = self._recv_exact(sock, 6)
            elif atyp == 0x04:
                _ = self._recv_exact(sock, 18)
            elif atyp == 0x03:
                domain_length = self._recv_exact(sock, 1)
                if len(domain_length) < 1:
                    return -1.0
                _ = self._recv_exact(sock, domain_length[0] + 2)
            else:
                return -1.0

            http_request = (
                "GET /generate_204 HTTP/1.1\r\n"
                "Host: connectivitycheck.gstatic.com\r\n"
                "Connection: close\r\n\r\n"
            )
            sock.sendall(http_request.encode())

            response_data = sock.recv(4096)
            elapsed = (time.perf_counter() - start_time) * 1000
            if response_data.startswith(b"HTTP/1.1 204") or response_data.startswith(b"HTTP/1.0 204"):
                return elapsed
            return -1.0

        except Exception:
            return -1.0
        finally:
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass

    def _wait_for_socks_startup(self, process: subprocess.Popen, port: int) -> bool:
        deadline = time.perf_counter() + self.startup_timeout
        time.sleep(self.startup_delay)
        while time.perf_counter() < deadline:
            if process.poll() is not None:
                return False
            probe = self._probe_local_port(port)
            if probe is True:
                return True
            time.sleep(0.1)
        return False

    @staticmethod
    def _probe_local_port(port: int) -> bool:
        try:
            with socket.create_connection(('127.0.0.1', port), timeout=0.4):
                return True
        except OSError:
            return False

    @staticmethod
    def _recv_exact(sock: socket.socket, size: int) -> bytes:
        buffer = bytearray()
        while len(buffer) < size:
            chunk = sock.recv(size - len(buffer))
            if not chunk:
                break
            buffer.extend(chunk)
        return bytes(buffer)
