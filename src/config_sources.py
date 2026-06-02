#!/usr/bin/env python3

import base64
import re
import ssl
import urllib.request
from typing import List, Set

from .parser import ConfigParser, ProxyConfig

_CONFIG_LINE = re.compile(r'^(vless|vmess|ss|trojan)://', re.IGNORECASE)


class ConfigSourceManager:
    SOURCES = [
        "https://raw.githubusercontent.com/barry-far/V2ray-Config/refs/heads/main/Splitted-By-Protocol/vless.txt",
        "https://raw.githubusercontent.com/barry-far/V2ray-Config/refs/heads/main/Splitted-By-Protocol/vmess.txt",
        "https://raw.githubusercontent.com/barry-far/V2ray-Config/refs/heads/main/Splitted-By-Protocol/ss.txt",
        "https://raw.githubusercontent.com/barry-far/V2ray-Config/refs/heads/main/Splitted-By-Protocol/trojan.txt",
        "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/v2ray/super-sub.txt",
        "https://raw.githubusercontent.com/ebrasha/free-v2ray-public-list/main/V2Ray-Config-By-EbraSha.txt",
    ]

    def __init__(self, timeout: float = 30.0, max_configs: int = 0):
        self.timeout = timeout
        self.max_configs = max_configs
        self.parser = ConfigParser()

    def get_configs_with_fallback(self) -> List[ProxyConfig]:
        configs = self.fetch_all_configs()
        if not configs:
            print("Warning: No configs fetched from any source")
        return configs

    def fetch_all_configs(self) -> List[ProxyConfig]:
        all_lines: List[str] = []

        for source_url in self.SOURCES:
            label = '/'.join(source_url.rstrip('/').split('/')[-2:])
            try:
                print(f"Fetching {label}...", end=" ", flush=True)
                lines = self._fetch_source(source_url)
                if lines:
                    all_lines.extend(lines)
                    print(f"OK ({len(lines)} lines)")
                else:
                    print("empty")
            except Exception as exc:
                print(f"failed ({str(exc)[:50]})")

        configs = self.deduplicate(all_lines)
        if self.max_configs > 0 and len(configs) > self.max_configs:
            print(f"Capping config list at {self.max_configs} (fetched {len(configs)})")
            configs = configs[: self.max_configs]
        return configs

    def _fetch_source(self, url: str) -> List[str]:
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE

        headers = {'User-Agent': 'v2ray-healthcheck/1.0'}
        request = urllib.request.Request(url, headers=headers)

        with urllib.request.urlopen(request, context=ssl_context, timeout=self.timeout) as response:
            content = response.read().decode('utf-8', errors='ignore')

        return self._extract_config_lines(content)

    def _extract_config_lines(self, content: str) -> List[str]:
        stripped = content.strip()
        if not stripped:
            return []

        lines = [line.strip() for line in stripped.splitlines() if line.strip()]
        if any(_CONFIG_LINE.match(line) for line in lines):
            return [line for line in lines if _CONFIG_LINE.match(line)]

        decoded = self._try_decode_subscription(stripped)
        if decoded:
            return [line for line in decoded if _CONFIG_LINE.match(line)]

        return []

    @staticmethod
    def _try_decode_subscription(content: str) -> List[str]:
        candidates = [content]
        if '\n' in content:
            candidates.append(''.join(content.split()))

        for candidate in candidates:
            try:
                padding = (-len(candidate)) % 4
                payload = candidate + ('=' * padding if padding else '')
                decoded = base64.b64decode(payload).decode('utf-8', errors='ignore')
                decoded_lines = [line.strip() for line in decoded.splitlines() if line.strip()]
                if any(_CONFIG_LINE.match(line) for line in decoded_lines):
                    return decoded_lines
            except Exception:
                continue
        return []

    def deduplicate(self, lines: List[str]) -> List[ProxyConfig]:
        seen_keys: Set[str] = set()
        seen_raw: Set[str] = set()
        configs: List[ProxyConfig] = []

        for line in lines:
            normalized_raw = self._normalize_raw_line(line)
            if not normalized_raw or not _CONFIG_LINE.match(normalized_raw):
                continue

            if normalized_raw in seen_raw:
                continue

            try:
                config = self.parser.parse_config_line(normalized_raw)
                if not config:
                    continue

                key = self._get_config_key(config)
                if key in seen_keys:
                    continue

                seen_keys.add(key)
                seen_raw.add(normalized_raw)
                configs.append(config)
            except Exception:
                continue

        return configs

    @staticmethod
    def _normalize_raw_line(line: str) -> str:
        cleaned = line.strip()
        if not cleaned:
            return ""
        return cleaned.replace('\u200b', '').replace('\ufeff', '')

    @staticmethod
    def _get_config_key(config: ProxyConfig) -> str:
        if config.protocol == 'vless':
            return (
                f"vless:{config.uuid}:{config.server}:{config.port}:"
                f"{config.network}:{config.security}:{config.path}:{config.host}:{config.flow}"
            )
        if config.protocol == 'vmess':
            return (
                f"vmess:{config.uuid}:{config.server}:{config.port}:"
                f"{config.network}:{config.path}:{config.host}:{config.alter_id}"
            )
        if config.protocol == 'ss':
            return f"ss:{config.method}:{config.password}:{config.server}:{config.port}"
        if config.protocol == 'trojan':
            return (
                f"trojan:{config.password}:{config.server}:{config.port}:"
                f"{config.network}:{config.path}:{config.sni}"
            )
        return config.raw_config.strip()
