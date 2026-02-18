#!/usr/bin/env python3

import json
import os
import socket
import struct
import subprocess
import tempfile
import time
from typing import Tuple, Optional
import ssl
from .parser import ProxyConfig

# Most of the code remains the same, but ensure log.level is set to "none" for Xray >=1.8+,
# so that warning/info messages don't clutter the output or cause confusion in CI.
# Xray's logging format changed in newer versions and "none" disables normal output.

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

        # Set log.level to "none" for completely quiet logging (Xray 1.8+ prefers "none" over "error")
        return {
            "log": {"loglevel": "none"},
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
        """
        Attempts to run Xray with a built config and validates its ability to proxy traffic.

        Returns:
            tuple: (success: bool, latency: float)
        """
        local_port = self._find_free_port()
        config = XrayConfigBuilder.build_config(proxy, local_port)

        config_fd, config_path = tempfile.mkstemp(suffix='.json')
        process = None
        try:
            with os.fdopen(config_fd, 'w') as f:
                json.dump(config, f)

            popen_args = {
                "args": [self.xray_path, '-c', config_path],
                "stdout": subprocess.PIPE,
                "stderr": subprocess.PIPE,
            }
            if os.name == 'nt':
                popen_args["creationflags"] = subprocess.CREATE_NO_WINDOW
            process = subprocess.Popen(**popen_args)

            # Wait for Xray to start up (increase, some images on CI may be slower)
            time.sleep(2.0)

            if process.poll() is not None:
                # Process exited early; print output for debugging.
                stdout_output = process.stdout.read().decode(errors="ignore") if process.stdout else ""
                stderr_output = process.stderr.read().decode(errors="ignore") if process.stderr else ""
                print("Xray exited early!")
                if stdout_output.strip():
                    print("---- STDOUT ----")
                    print(stdout_output)
                if stderr_output.strip():
                    print("---- STDERR ----")
                    print(stderr_output)
                print("----------------")
                return False, -1

            latency = self._test_through_proxy('127.0.0.1', local_port)

            # Always try to terminate the process gracefully.
            process.terminate()
            try:
                stdout_output, stderr_output = process.communicate(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                stdout_output, stderr_output = process.communicate()

            # Decode outputs for logging
            decoded_stderr = stderr_output.decode(errors="ignore") if isinstance(stderr_output, bytes) else (stderr_output or "")
            decoded_stdout = stdout_output.decode(errors="ignore") if isinstance(stdout_output, bytes) else (stdout_output or "")
            if decoded_stdout.strip():
                print("---- STDOUT ----")
                print(decoded_stdout)
            if decoded_stderr.strip():
                print("---- STDERR ----")
                print(decoded_stderr)

            if latency <= 0:
                print("Xray failed to proxy request (latency <= 0).")

            return latency > 0, latency

        except Exception as exc:
            print(f"Exception in test_config_with_xray: {exc}")
            if process is not None:
                try:
                    process.terminate()
                except Exception:
                    pass
                try:
                    stdout_output, stderr_output = process.communicate(timeout=1)
                    decoded_stderr = stderr_output.decode(errors="ignore") if isinstance(stderr_output, bytes) else (stderr_output or "")
                    decoded_stdout = stdout_output.decode(errors="ignore") if isinstance(stdout_output, bytes) else (stdout_output or "")
                    if decoded_stdout.strip():
                        print("---- STDOUT ----")
                        print(decoded_stdout)
                    if decoded_stderr.strip():
                        print("---- STDERR ----")
                        print(decoded_stderr)
                except Exception:
                    pass
            return False, -1
        finally:
            try:
                os.unlink(config_path)
            except Exception:
                pass

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

            # SOCKS5 greeting
            sock.sendall(b"\x05\x01\x00")
            if sock.recv(2) != b"\x05\x00":
                sock.close()
                return -1

            # CONNECT to example.com:443 using domain type
            domain = b"example.com"
            request = (
                b"\x05\x01\x00\x03" +
                bytes([len(domain)]) +
                domain +
                struct.pack(">H", 443)
            )
            sock.sendall(request)

            response = sock.recv(10)
            if len(response) < 2 or response[1] != 0x00:
                sock.close()
                return -1

            # Wrap in TLS
            context = ssl.create_default_context()
            tls_sock = context.wrap_socket(sock, server_hostname="example.com")

            # Force handshake
            tls_sock.do_handshake()

            tls_sock.close()

            return (time.time() - start_time) * 1000

        except Exception:
            return -1

