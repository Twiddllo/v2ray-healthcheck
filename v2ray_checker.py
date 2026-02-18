#!/usr/bin/env python3

import os
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Tuple

from src.parser import ConfigParser, ProxyConfig
from src.config_sources import ConfigSourceManager
from src.tcp_checker import TCPPreChecker
from src.xray_validator import XrayValidator


class ConfigCheckerBot:
    def __init__(self, output_file: str = "result.txt", max_workers: int = None):
        self.output_file = output_file
        self.max_workers = max_workers or min(100, (os.cpu_count() or 4) * 3)
        self.source_manager = ConfigSourceManager()
        self.tcp_checker = TCPPreChecker()
        self.xray_validator = XrayValidator()
        self.working_configs: List[Tuple[ProxyConfig, float]] = []
        self.tcp_passed_configs: List[ProxyConfig] = []
        self.lock = threading.Lock()
        self.tested_count = 0
        self.tcp_passed_count = 0

    def run(self):
        print("=" * 60)
        print("V2Ray Config Checker - Production Edition")
        print("=" * 60)

        print("\nPhase 0: Fetching remote configs...")
        print("-" * 60)
        configs = self.source_manager.get_configs_with_fallback()

        if not configs:
            print("No configs fetched from sources")
            return

        print(f"\nTotal configs after deduplication: {len(configs)}")

        print("\nPhase 1: TCP Precheck")
        print("-" * 60)
        start_phase1 = time.time()

        self.tcp_passed_configs = self._run_tcp_precheck(configs)
        elapsed_phase1 = time.time() - start_phase1

        print(f"TCP Check Complete: {len(self.tcp_passed_configs)}/{len(configs)} passed ({len(self.tcp_passed_configs)/len(configs)*100:.1f}%)")
        print(f"Time: {elapsed_phase1:.1f}s\n")

        if not self.tcp_passed_configs:
            print("No configs passed TCP precheck")
            self.save_results()
            return

        print("Phase 2: Xray Validation")
        print("-" * 60)
        start_phase2 = time.time()

        self._run_xray_validation(self.tcp_passed_configs)
        elapsed_phase2 = time.time() - start_phase2

        self.working_configs.sort(key=lambda x: x[1])
        self.save_results()

        print("\n" + "=" * 60)
        print(f"Total configs tested: {len(configs)}")
        print(f"TCP passed: {len(self.tcp_passed_configs)}")
        print(f"Xray verified: {len(self.working_configs)}")
        print(f"Phase 1 time: {elapsed_phase1:.1f}s")
        print(f"Phase 2 time: {elapsed_phase2:.1f}s")
        print(f"Results saved to: {self.output_file}")
        print("=" * 60)

        if self.working_configs:
            print("\nTop 10 fastest configs:")
            for i, (config, latency) in enumerate(self.working_configs[:10], 1):
                print(f"  {i}. [{config.protocol.upper()}] {config.name[:40]} - {latency:.0f}ms")

    def _run_tcp_precheck(self, configs: List[ProxyConfig]) -> List[ProxyConfig]:
        passed = []
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {executor.submit(self._test_tcp, config): config for config in configs}

            for i, future in enumerate(as_completed(futures), 1):
                try:
                    result = future.result()
                    if result:
                        passed.append(result)
                except Exception:
                    pass

                if i % 100 == 0:
                    print(f"  Tested {i}/{len(configs)} configs...")

        return passed

    def _test_tcp(self, config: ProxyConfig) -> ProxyConfig:
        success, msg = self.tcp_checker.test_config_tcp(config)
        if success:
            return config
        return None

    def _run_xray_validation(self, configs: List[ProxyConfig]):
        with ThreadPoolExecutor(max_workers=4) as executor:
            futures = {executor.submit(self._test_xray, config): config for config in configs}

            for i, future in enumerate(as_completed(futures), 1):
                try:
                    success, latency = future.result()
                    if success and latency > 0:
                        config = futures[future]
                        with self.lock:
                            self.working_configs.append((config, latency))
                except Exception:
                    pass

                if i % 10 == 0:
                    with self.lock:
                        print(f"  Verified {i}/{len(configs)} configs... ({len(self.working_configs)} working)")

    def _test_xray(self, config: ProxyConfig) -> Tuple[bool, float]:
        try:
            return self.xray_validator.test_config_with_xray(config)
        except Exception:
            return False, -1

    def save_results(self):
        with open(self.output_file, 'w', encoding='utf-8') as f:
            f.write("# V2Ray Config Checker Results\n")
            f.write(f"# Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"# Working configs: {len(self.working_configs)}\n")
            f.write("#" + "=" * 50 + "\n\n")

            for config, latency in self.working_configs:
                f.write(f"# [{config.protocol.upper()}] Latency: {latency:.0f}ms | {config.name}\n")
                f.write(f"{config.raw_config}\n\n")


def main():
    bot = ConfigCheckerBot()
    bot.run()


if __name__ == "__main__":
    main()
