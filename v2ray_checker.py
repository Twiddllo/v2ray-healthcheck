#!/usr/bin/env python3

import os
import sys
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Optional, Tuple

from src.parser import ProxyConfig
from src.config_sources import ConfigSourceManager
from src.tcp_checker import TCPPreChecker
from src.xray_validator import XrayValidator


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name, '').strip()
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


class ConfigCheckerBot:
    def __init__(
        self,
        output_file: str = "result.txt",
        max_workers: Optional[int] = None,
        max_configs: Optional[int] = None,
        xray_workers: Optional[int] = None,
    ):
        cpu = os.cpu_count() or 4
        self.output_file = output_file
        self.max_workers = max_workers or min(80, cpu * 4)
        self.xray_workers = xray_workers or min(6, max(2, cpu // 2))
        self.max_configs = max_configs if max_configs is not None else _env_int('V2RAY_MAX_CONFIGS', 0)

        self.source_manager = ConfigSourceManager(max_configs=self.max_configs)
        self.tcp_checker = TCPPreChecker(timeout=_env_int('V2RAY_TCP_TIMEOUT', 5))
        self.xray_validator = XrayValidator(
            xray_path=os.environ.get('XRAY_PATH', 'xray'),
            startup_delay=float(os.environ.get('XRAY_STARTUP_DELAY', '0.6')),
        )

        self.working_configs: List[Tuple[ProxyConfig, float]] = []
        self.tcp_passed_configs: List[ProxyConfig] = []
        self.lock = threading.Lock()

    def run(self) -> int:
        print("=" * 60)
        print("V2Ray Config Checker")
        print("=" * 60)

        print("\nPhase 0: Fetching remote configs...")
        print("-" * 60)
        configs = self.source_manager.get_configs_with_fallback()
        if not configs:
            print("No configs fetched from sources")
            self.save_results()
            return 1

        print(f"\nTotal configs after deduplication: {len(configs)}")

        print("\nPhase 1: TCP precheck")
        print("-" * 60)
        start_phase1 = time.time()
        self.tcp_passed_configs = self._run_tcp_precheck(configs)
        elapsed_phase1 = time.time() - start_phase1

        passed_pct = (len(self.tcp_passed_configs) / len(configs)) * 100
        print(
            f"TCP complete: {len(self.tcp_passed_configs)}/{len(configs)} passed "
            f"({passed_pct:.1f}%) in {elapsed_phase1:.1f}s"
        )

        if not self.tcp_passed_configs:
            print("No configs passed TCP precheck")
            self.save_results()
            return 0

        print("\nPhase 2: Xray validation")
        print("-" * 60)
        start_phase2 = time.time()
        self._run_xray_validation(self.tcp_passed_configs)
        elapsed_phase2 = time.time() - start_phase2

        self.working_configs.sort(key=lambda item: item[1])
        self.save_results()

        print("\n" + "=" * 60)
        print(f"Fetched: {len(configs)}")
        print(f"TCP passed: {len(self.tcp_passed_configs)}")
        print(f"Xray verified: {len(self.working_configs)}")
        print(f"Phase 1: {elapsed_phase1:.1f}s | Phase 2: {elapsed_phase2:.1f}s")
        print(f"Results: {self.output_file}")
        print("=" * 60)

        if self.working_configs:
            print("\nTop 10:")
            for index, (config, latency) in enumerate(self.working_configs[:10], 1):
                print(f"  {index}. [{config.protocol.upper()}] {config.name[:40]} - {latency:.0f}ms")

        return 0

    def has_working_configs(self) -> bool:
        return bool(self.working_configs)

    def _run_tcp_precheck(self, configs: List[ProxyConfig]) -> List[ProxyConfig]:
        passed: List[ProxyConfig] = []
        total = len(configs)

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {executor.submit(self._test_tcp, config): config for config in configs}

            for index, future in enumerate(as_completed(futures), 1):
                try:
                    result = future.result()
                    if result is not None:
                        passed.append(result)
                except Exception:
                    pass

                if index % 200 == 0 or index == total:
                    print(f"  TCP progress: {index}/{total}")

        return passed

    def _test_tcp(self, config: ProxyConfig) -> Optional[ProxyConfig]:
        success, _ = self.tcp_checker.test_config_tcp(config)
        return config if success else None

    def _run_xray_validation(self, configs: List[ProxyConfig]) -> None:
        total = len(configs)

        with ThreadPoolExecutor(max_workers=self.xray_workers) as executor:
            futures = {executor.submit(self._test_xray, config): config for config in configs}

            for index, future in enumerate(as_completed(futures), 1):
                try:
                    success, latency = future.result()
                    if success and latency > 0:
                        config = futures[future]
                        with self.lock:
                            self.working_configs.append((config, latency))
                except Exception:
                    pass

                if index % 20 == 0 or index == total:
                    with self.lock:
                        working = len(self.working_configs)
                    print(f"  Xray progress: {index}/{total} ({working} working)")

    def _test_xray(self, config: ProxyConfig) -> Tuple[bool, float]:
        try:
            return self.xray_validator.test_config_with_xray(config)
        except Exception:
            return False, -1.0

    def save_results(self) -> None:
        with open(self.output_file, 'w', encoding='utf-8') as handle:
            handle.write("# V2Ray Config Checker Results\n")
            handle.write(f"# Generated: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}\n")
            handle.write(f"# Working configs: {len(self.working_configs)}\n")
            handle.write("#" + "=" * 50 + "\n\n")

            for config, latency in self.working_configs:
                handle.write(f"# [{config.protocol.upper()}] Latency: {latency:.0f}ms | {config.name}\n")
                handle.write(f"{config.raw_config}\n\n")


def main() -> None:
    bot = ConfigCheckerBot()
    raise SystemExit(bot.run())


if __name__ == "__main__":
    main()
