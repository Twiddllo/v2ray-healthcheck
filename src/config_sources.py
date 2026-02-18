#!/usr/bin/env python3

import urllib.request
import ssl
import json
import base64
from typing import List, Set, Optional
from .parser import ConfigParser, ProxyConfig


class ConfigSourceManager:
    SOURCES = [
        "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/v2ray/all_sub.txt",
        "https://raw.githubusercontent.com/barry-far/V2ray-Config/main/All_Configs_Sub.txt",
        "https://raw.githubusercontent.com/ebrasha/free-v2ray-public-list/main/all_extracted_configs.txt",
    ]

    def __init__(self, timeout: float = 30.0):
        self.timeout = timeout
        self.parser = ConfigParser()

    def get_configs_with_fallback(self) -> List[ProxyConfig]:
        configs = self.fetch_all_configs()
        if not configs:
            print("Warning: No configs fetched from any source")
        return configs

    def fetch_all_configs(self) -> List[ProxyConfig]:
        all_lines = []

        for source_url in self.SOURCES:
            try:
                print(f"Fetching from {source_url.split('/')[-2]}/{source_url.split('/')[-1]}...", end=" ")
                lines = self._fetch_source(source_url)
                if lines:
                    all_lines.extend(lines)
                    print(f"OK ({len(lines)} configs)")
                else:
                    print("Empty")
            except Exception as e:
                print(f"Failed: {str(e)[:40]}")

        return self.deduplicate(all_lines)

    def _fetch_source(self, url: str) -> List[str]:
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE

        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        req = urllib.request.Request(url, headers=headers)

        with urllib.request.urlopen(req, context=ssl_context, timeout=self.timeout) as response:
            content = response.read().decode('utf-8', errors='ignore')
            return [line.strip() for line in content.split('\n') if line.strip()]

    def deduplicate(self, lines: List[str]) -> List[ProxyConfig]:
        seen_keys: Set[str] = set()
        configs = []

        for line in lines:
            try:
                config = self.parser.parse_config_line(line)
                if config:
                    key = self._get_config_key(config)
                    if key not in seen_keys:
                        seen_keys.add(key)
                        configs.append(config)
            except Exception:
                pass

        return configs

    @staticmethod
    def _get_config_key(config: ProxyConfig) -> str:
        if config.protocol == 'vless':
            return f"vless:{config.uuid}:{config.server}:{config.port}:{config.network}:{config.security}:{config.path}:{config.host}"
        elif config.protocol == 'vmess':
            return f"vmess:{config.uuid}:{config.server}:{config.port}:{config.network}:{config.path}:{config.host}"
        elif config.protocol == 'ss':
            return f"ss:{config.method}:{config.server}:{config.port}"
        elif config.protocol == 'trojan':
            return f"trojan:{config.password}:{config.server}:{config.port}:{config.network}:{config.path}:{config.sni}"
        else:
            return config.raw_config
