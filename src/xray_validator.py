#!/usr/bin/env python3

import json
import os
import socket
import struct
import subprocess
import tempfile
import time
from typing import Tuple, Optional

from .parser import ProxyConfig


class XrayConfigBuilder:
    @staticmethod
    def build_config(proxy: ProxyConfig, local_port: int = 10808) -> dict:
        inbound = {
            "port": local_port,
            "protocol": "socks",
            "settings": {
                "auth": "noauth",
                "udp": True,
                "ip": "127.0.0.1"
            },
            "sniffing": {
                "enabled": True,
                "destOverride": ["http", "tls"]
            }
        }

        outbound = XrayConfigBuilder._build_outbound(proxy)

        return {
            "log": {"loglevel": "error"},
            "inbounds": [inbound],
            "outbounds": [outbound, {"protocol": "freedom", "tag": "direct"}],
            "routing": {
                "rules": [
                    {"type": "field", "outboundTag": "direct", "ip": ["geoip:private"]}
                ]
            }
        }

    @staticmethod
    def _build_outbound(proxy: ProxyConfig) -> dict:
        if proxy.protocol == 'vless':
            return XrayConfigBuilder._build_vless_outbound(proxy)
        elif proxy.protocol == 'vmess':
            return XrayConfigBuilder._build_vmess_outbound(proxy)
        elif proxy.protocol == 'ss':
            return XrayConfigBuilder._build_ss_outbound(proxy)
        elif proxy.protocol == 'trojan':
            return XrayConfigBuilder._build_trojan_outbound(proxy)
        else:
            raise ValueError(f"Unsupported protocol: {proxy.protocol}")

    @staticmethod
    def _build_vless_outbound(proxy: ProxyConfig) -> dict:
        stream_settings = {"network": proxy.network or "tcp"}

        if proxy.tls or proxy.security in ['tls', 'xtls', 'reality']:
            tls_settings = {
                "serverName": proxy.sni or proxy.host or proxy.server,
                "allowInsecure": False
            }

            if proxy.fp:
                tls_settings["fingerprint"] = proxy.fp

            if proxy.security == 'reality' and proxy.pbk:
                tls_settings["publicKey"] = proxy.pbk
                if proxy.sid:
                    tls_settings["shortId"] = proxy.sid
                tls_settings["spiderX"] = ""
                stream_settings["security"] = "reality"
                stream_settings["realitySettings"] = tls_settings
            else:
                stream_settings["security"] = "tls"
                stream_settings["tlsSettings"] = tls_settings

        if proxy.network == 'ws':
            stream_settings["wsSettings"] = {
                "path": proxy.path or "/",
                "headers": {"Host": proxy.host or proxy.server}
            }
        elif proxy.network == 'grpc':
            stream_settings["grpcSettings"] = {
                "serviceName": proxy.path or "",
                "multiMode": False
            }
        elif proxy.network == 'h2':
            stream_settings["httpSettings"] = {
                "path": proxy.path or "/",
                "host": [proxy.host or proxy.server]
            }

        settings = {
            "vnext": [{
                "address": proxy.server,
                "port": proxy.port,
                "users": [{
                    "id": proxy.uuid,
                    "encryption": "none",
                    "flow": proxy.flow or ""
                }]
            }]
        }

        return {
            "protocol": "vless",
            "settings": settings,
            "streamSettings": stream_settings,
            "tag": "proxy"
        }

    @staticmethod
    def _build_vmess_outbound(proxy: ProxyConfig) -> dict:
        stream_settings = {"network": proxy.network or "tcp"}

        if proxy.tls:
            stream_settings["security"] = "tls"
            stream_settings["tlsSettings"] = {
                "serverName": proxy.host or proxy.server,
                "allowInsecure": False
            }

        if proxy.network == 'ws':
            stream_settings["wsSettings"] = {
                "path": proxy.path or "/",
                "headers": {"Host": proxy.host or proxy.server}
            }
        elif proxy.network == 'grpc':
            stream_settings["grpcSettings"] = {
                "serviceName": proxy.path or ""
            }

        settings = {
            "vnext": [{
                "address": proxy.server,
                "port": proxy.port,
                "users": [{
                    "id": proxy.uuid,
                    "alterId": proxy.alter_id or 0,
                    "security": "auto"
                }]
            }]
        }

        return {
            "protocol": "vmess",
            "settings": settings,
            "streamSettings": stream_settings,
            "tag": "proxy"
        }

    @staticmethod
    def _build_ss_outbound(proxy: ProxyConfig) -> dict:
        settings = {
            "servers": [{
                "address": proxy.server,
                "port": proxy.port,
                "method": proxy.method or "aes-256-gcm",
                "password": proxy.password or ""
            }]
        }

        return {
            "protocol": "shadowsocks",
            "settings": settings,
            "streamSettings": {},
            "tag": "proxy"
        }

    @staticmethod
    def _build_trojan_outbound(proxy: ProxyConfig) -> dict:
        stream_settings = {
            "network": proxy.network or "tcp",
            "security": "tls",
            "tlsSettings": {
                "serverName": proxy.sni or proxy.host or proxy.server,
                "allowInsecure": False
            }
        }

        if proxy.network == 'ws':
            stream_settings["wsSettings"] = {
                "path": proxy.path or "/",
                "headers": {"Host": proxy.host or proxy.server}
            }
        elif proxy.network == 'grpc':
            stream_settings["grpcSettings"] = {
                "serviceName": proxy.path or ""
            }

        settings = {
            "servers": [{
                "address": proxy.server,
                "port": proxy.port,
                "password": proxy.password,
                "flow": ""
            }]
        }

        return {
            "protocol": "trojan",
            "settings": settings,
            "streamSettings": stream_settings,
            "tag": "proxy"
        }


class XrayValidator:
    def __init__(self, xray_path: str = "xray"):
        self.xray_path = xray_path
        self.timeout = 10

    def test_config_with_xray(self, proxy: ProxyConfig) -> Tuple[bool, float]:
        try:
            local_port = self._find_free_port()
            config = XrayConfigBuilder.build_config(proxy, local_port)

            config_fd, config_path = tempfile.mkstemp(suffix='.json')
            try:
                with os.fdopen(config_fd, 'w') as f:
                    json.dump(config, f)

                process = subprocess.Popen(
                    [self.xray_path, '-c', config_path],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0
                )

                time.sleep(0.5)

                if process.poll() is not None:
                    return False, -1

                latency = self._test_through_proxy('127.0.0.1', local_port)

                process.terminate()
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill()

                return latency > 0, latency

            finally:
                try:
                    os.unlink(config_path)
                except Exception:
                    pass

        except Exception:
            return False, -1

    def _find_free_port(self) -> int:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(('127.0.0.1', 0))
        port = sock.getsockname()[1]
        sock.close()
        return port

    def _test_through_proxy(self, proxy_host: str, proxy_port: int) -> float:
        try:
            start_time = time.time()

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((proxy_host, proxy_port))

            sock.sendall(bytes([0x05, 0x01, 0x00]))
            response = sock.recv(2)
            if response[0] != 0x05 or response[1] != 0x00:
                sock.close()
                return -1

            target_addr = socket.getaddrinfo("www.google.com", 80, socket.AF_INET)[0][4][0]
            request = bytes([0x05, 0x01, 0x00, 0x01]) + socket.inet_aton(target_addr) + struct.pack('>H', 80)
            sock.sendall(request)

            response = sock.recv(10)
            if response[1] != 0x00:
                sock.close()
                return -1

            http_request = "GET /generate_204 HTTP/1.1\r\nHost: www.google.com\r\nConnection: close\r\n\r\n"
            sock.sendall(http_request.encode())

            sock.settimeout(10)
            response_data = b""
            try:
                while True:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    response_data += chunk
            except socket.timeout:
                pass

            sock.close()

            elapsed = (time.time() - start_time) * 1000

            if b"204" in response_data or b"HTTP/1.1" in response_data:
                return elapsed

            return -1

        except Exception:
            return -1
