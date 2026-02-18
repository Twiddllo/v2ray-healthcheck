#!/usr/bin/env python3

import base64
import json
import urllib.parse
from dataclasses import dataclass
from typing import Optional


@dataclass
class ProxyConfig:
    protocol: str
    name: str
    server: str
    port: int
    raw_config: str

    uuid: Optional[str] = None
    password: Optional[str] = None
    method: Optional[str] = None
    alter_id: Optional[int] = None
    network: Optional[str] = None
    security: Optional[str] = None
    path: Optional[str] = None
    host: Optional[str] = None
    tls: Optional[bool] = None
    sni: Optional[str] = None
    flow: Optional[str] = None
    pbk: Optional[str] = None
    sid: Optional[str] = None
    fp: Optional[str] = None


class ConfigParser:
    @staticmethod
    def parse_config_line(line: str) -> Optional[ProxyConfig]:
        line = line.strip()
        if not line:
            return None

        if line.startswith('vless://'):
            return ConfigParser._parse_vless(line)
        elif line.startswith('vmess://'):
            return ConfigParser._parse_vmess(line)
        elif line.startswith('ss://'):
            return ConfigParser._parse_ss(line)
        elif line.startswith('trojan://'):
            return ConfigParser._parse_trojan(line)

        return None

    @staticmethod
    def _parse_vless(url: str) -> Optional[ProxyConfig]:
        try:
            parsed = urllib.parse.urlparse(url)

            uuid = parsed.username
            server = parsed.hostname
            port = parsed.port

            if not all([uuid, server, port]):
                return None

            params = urllib.parse.parse_qs(parsed.query)
            name = urllib.parse.unquote(parsed.fragment) if parsed.fragment else f"vless_{server}"

            config = ProxyConfig(
                protocol='vless',
                name=name,
                server=server,
                port=port,
                raw_config=url,
                uuid=uuid,
                network=params.get('type', ['tcp'])[0],
                security=params.get('security', ['none'])[0],
                path=params.get('path', [''])[0],
                host=params.get('host', [''])[0],
                sni=params.get('sni', [''])[0] or params.get('peer', [''])[0],
                flow=params.get('flow', [None])[0],
                pbk=params.get('pbk', [None])[0],
                sid=params.get('sid', [None])[0],
                fp=params.get('fp', [None])[0],
                tls=params.get('security', ['none'])[0] in ['tls', 'xtls', 'reality']
            )
            return config
        except Exception:
            return None

    @staticmethod
    def _parse_vmess(url: str) -> Optional[ProxyConfig]:
        try:
            b64_data = url[8:]
            padding = 4 - len(b64_data) % 4
            if padding != 4:
                b64_data += '=' * padding

            json_str = base64.b64decode(b64_data).decode('utf-8')
            data = json.loads(json_str)

            config = ProxyConfig(
                protocol='vmess',
                name=data.get('ps', f"vmess_{data.get('add', 'unknown')}"),
                server=data.get('add', ''),
                port=int(data.get('port', 0)),
                raw_config=url,
                uuid=data.get('id', ''),
                alter_id=int(data.get('aid', 0)),
                network=data.get('net', 'tcp'),
                security=data.get('tls', 'none'),
                path=data.get('path', ''),
                host=data.get('host', ''),
                tls=data.get('tls', '') == 'tls'
            )
            return config
        except Exception:
            return None

    @staticmethod
    def _parse_ss(url: str) -> Optional[ProxyConfig]:
        try:
            parsed = urllib.parse.urlparse(url)

            server = parsed.hostname
            port = parsed.port
            name = urllib.parse.unquote(parsed.fragment) if parsed.fragment else f"ss_{server}"

            if not server or not port:
                return None

            user_info = parsed.username
            if parsed.password:
                method = urllib.parse.unquote(user_info)
                password = urllib.parse.unquote(parsed.password)
            else:
                try:
                    padding = 4 - len(user_info) % 4
                    if padding != 4:
                        user_info += '=' * padding
                    decoded = base64.b64decode(user_info).decode('utf-8')
                    method, password = decoded.split(':', 1)
                except Exception:
                    method = 'aes-256-gcm'
                    password = user_info

            config = ProxyConfig(
                protocol='ss',
                name=name,
                server=server,
                port=port,
                raw_config=url,
                method=method,
                password=password
            )
            return config
        except Exception:
            return None

    @staticmethod
    def _parse_trojan(url: str) -> Optional[ProxyConfig]:
        try:
            parsed = urllib.parse.urlparse(url)

            password = parsed.username
            server = parsed.hostname
            port = parsed.port

            if not all([password, server, port]):
                return None

            params = urllib.parse.parse_qs(parsed.query)
            name = urllib.parse.unquote(parsed.fragment) if parsed.fragment else f"trojan_{server}"

            config = ProxyConfig(
                protocol='trojan',
                name=name,
                server=server,
                port=port,
                raw_config=url,
                password=password,
                network=params.get('type', ['tcp'])[0],
                path=params.get('path', [''])[0],
                host=params.get('host', [''])[0],
                sni=params.get('sni', [''])[0] or params.get('peer', [''])[0],
                tls=True
            )
            return config
        except Exception:
            return None
