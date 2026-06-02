#!/usr/bin/env python3

import base64
import binascii
import json
import urllib.parse
from dataclasses import dataclass
from typing import Optional

_PROTOCOL_PREFIXES = ('vless://', 'vmess://', 'ss://', 'trojan://')
_DEFAULT_PORTS = {'vless': 443, 'vmess': 443, 'trojan': 443, 'ss': 8388}


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
        if not line or line.startswith('#'):
            return None

        lower = line.lower()
        if lower.startswith('vless://'):
            return ConfigParser._parse_vless(line)
        if lower.startswith('vmess://'):
            return ConfigParser._parse_vmess(line)
        if lower.startswith('ss://'):
            return ConfigParser._parse_ss(line)
        if lower.startswith('trojan://'):
            return ConfigParser._parse_trojan(line)

        return None

    @staticmethod
    def _decode_base64(data: str) -> str:
        data = data.strip()
        data = data.replace('-', '+').replace('_', '/')
        padding = (-len(data)) % 4
        if padding:
            data += '=' * padding
        return base64.b64decode(data, validate=False).decode('utf-8', errors='ignore')

    @staticmethod
    def _resolve_port(parsed: urllib.parse.ParseResult, protocol: str) -> Optional[int]:
        if parsed.port is not None:
            return parsed.port
        return _DEFAULT_PORTS.get(protocol)

    @staticmethod
    def _parse_vless(url: str) -> Optional[ProxyConfig]:
        try:
            parsed = urllib.parse.urlparse(url)
            uuid = parsed.username
            server = parsed.hostname
            port = ConfigParser._resolve_port(parsed, 'vless')

            if not uuid or not server or not port:
                return None

            params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
            security = params.get('security', ['none'])[0] or 'none'
            name = urllib.parse.unquote(parsed.fragment) if parsed.fragment else f"vless_{server}"

            return ProxyConfig(
                protocol='vless',
                name=name,
                server=server,
                port=port,
                raw_config=url,
                uuid=uuid,
                network=params.get('type', ['tcp'])[0] or 'tcp',
                security=security,
                path=params.get('path', [''])[0],
                host=params.get('host', [''])[0],
                sni=params.get('sni', [''])[0] or params.get('peer', [''])[0],
                flow=params.get('flow', [None])[0],
                pbk=params.get('pbk', [None])[0],
                sid=params.get('sid', [None])[0],
                fp=params.get('fp', [None])[0],
                tls=security in ('tls', 'xtls', 'reality'),
            )
        except Exception:
            return None

    @staticmethod
    def _parse_vmess(url: str) -> Optional[ProxyConfig]:
        try:
            payload = url.split('://', 1)[1]
            payload = payload.split('#', 1)[0]
            json_str = ConfigParser._decode_base64(payload)
            data = json.loads(json_str)

            server = data.get('add', '')
            port = int(data.get('port', 0) or 0)
            if not server or port <= 0:
                return None

            tls_value = str(data.get('tls', '') or '').lower()
            security = 'tls' if tls_value in ('tls', '1', 'true') else 'none'

            return ProxyConfig(
                protocol='vmess',
                name=data.get('ps', f"vmess_{server}"),
                server=server,
                port=port,
                raw_config=url,
                uuid=data.get('id', ''),
                alter_id=int(data.get('aid', 0) or 0),
                network=data.get('net', 'tcp') or 'tcp',
                security=security,
                path=data.get('path', '') or '',
                host=data.get('host', '') or '',
                sni=data.get('sni', '') or data.get('host', '') or '',
                tls=security == 'tls',
            )
        except Exception:
            return None

    @staticmethod
    def _parse_ss(url: str) -> Optional[ProxyConfig]:
        try:
            payload = url[5:]
            payload, _, fragment = payload.partition('#')
            payload, _, _ = payload.partition('?')

            name = urllib.parse.unquote(fragment) if fragment else ''
            credentials = payload
            server = None
            port = None

            if '@' in payload:
                credentials, endpoint = payload.rsplit('@', 1)
                endpoint_parsed = urllib.parse.urlparse(f'//{endpoint}')
                server = endpoint_parsed.hostname
                port = endpoint_parsed.port or _DEFAULT_PORTS['ss']

            method, password = ConfigParser._parse_ss_credentials(credentials)
            if not method or password is None:
                return None

            if not server or not port:
                try:
                    decoded_payload = ConfigParser._decode_base64(credentials)
                    if '@' in decoded_payload:
                        credentials, endpoint = decoded_payload.rsplit('@', 1)
                        endpoint_parsed = urllib.parse.urlparse(f'//{endpoint}')
                        server = endpoint_parsed.hostname
                        port = endpoint_parsed.port or _DEFAULT_PORTS['ss']
                        method, password = ConfigParser._parse_ss_credentials(credentials)
                except Exception:
                    pass

            if not server or not port:
                return None

            if not name:
                name = f"ss_{server}"

            return ProxyConfig(
                protocol='ss',
                name=name,
                server=server,
                port=port,
                raw_config=url,
                method=method or 'aes-256-gcm',
                password=password or '',
            )
        except Exception:
            return None

    @staticmethod
    def _parse_ss_credentials(credentials: str) -> tuple:
        user_info = urllib.parse.unquote(credentials)
        if ':' in user_info:
            method, password = user_info.split(':', 1)
            if method and password:
                return method, password

        try:
            decoded = ConfigParser._decode_base64(user_info)
            if ':' in decoded:
                method, password = decoded.split(':', 1)
                if method and password:
                    return method, password
        except (ValueError, binascii.Error, UnicodeError):
            pass

        return None, None

    @staticmethod
    def _parse_trojan(url: str) -> Optional[ProxyConfig]:
        try:
            parsed = urllib.parse.urlparse(url)
            password = parsed.username
            server = parsed.hostname
            port = ConfigParser._resolve_port(parsed, 'trojan')

            if not password or not server or not port:
                return None

            params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
            name = urllib.parse.unquote(parsed.fragment) if parsed.fragment else f"trojan_{server}"

            return ProxyConfig(
                protocol='trojan',
                name=name,
                server=server,
                port=port,
                raw_config=url,
                password=password,
                network=params.get('type', ['tcp'])[0] or 'tcp',
                path=params.get('path', [''])[0],
                host=params.get('host', [''])[0],
                sni=params.get('sni', [''])[0] or params.get('peer', [''])[0],
                tls=True,
            )
        except Exception:
            return None

    @staticmethod
    def is_config_line(line: str) -> bool:
        line = line.strip().lower()
        return any(line.startswith(prefix) for prefix in _PROTOCOL_PREFIXES)
