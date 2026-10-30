import os
import random
import threading
import time
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


def _log(message: str = '') -> None:
    print(message, flush=True)


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
        self.max_workers = max_workers or _env_int('V2RAY_TCP_WORKERS', min(128, max(16, cpu * 8)))
        self.xray_workers = xray_workers or _env_int('V2RAY_XRAY_WORKERS', min(8, max(2, cpu)))
        self.max_configs = max_configs if max_configs is not None else _env_int('V2RAY_MAX_CONFIGS', 0)

        self.deadline_seconds = _env_int('V2RAY_DEADLINE_SECONDS', 0)
        self.started_at = time.monotonic()

        self.source_manager = ConfigSourceManager(max_configs=self.max_configs)
        self.tcp_checker = TCPPreChecker(timeout=_env_int('V2RAY_TCP_TIMEOUT', 5))
        self.xray_validator = XrayValidator(
            xray_path=os.environ.get('XRAY_PATH', 'xray'),
            startup_delay=float(os.environ.get('XRAY_STARTUP_DELAY', '0.25')),
        )

        self.working_configs: List[Tuple[ProxyConfig, float]] = []
        self.tcp_passed_configs: List[ProxyConfig] = []
        self.total_fetched: int = 0
        self.phase1_seconds: float = 0.0
        self.phase2_seconds: float = 0.0
        self.stopped_early: bool = False
        self.lock = threading.Lock()

    def _deadline_reached(self) -> bool:
        if self.deadline_seconds <= 0:
            return False
        return (time.monotonic() - self.started_at) >= self.deadline_seconds

    def run(self) -> int:
        _log("=" * 60)
        _log("V2Ray Config Checker")
        _log("=" * 60)
        if self.deadline_seconds > 0:
            _log(f"Run budget: {self.deadline_seconds}s (results are committed even if stopped early)")

        _log("\nPhase 0: Fetching remote configs...")
        _log("-" * 60)
        configs = self.source_manager.get_configs_with_fallback()
        if not configs:
            _log("No configs fetched from sources")
            self.total_fetched = 0
            self.save_results()
            return 1

        self.total_fetched = len(configs)

        random.shuffle(configs)

        _log(f"\nTotal configs after deduplication: {len(configs)}")

        _log("\nPhase 1: TCP precheck")
        _log("-" * 60)
        start_phase1 = time.time()
        self.tcp_passed_configs = self._run_tcp_precheck(configs)
        elapsed_phase1 = time.time() - start_phase1
        self.phase1_seconds = elapsed_phase1

        passed_pct = (len(self.tcp_passed_configs) / len(configs)) * 100
        _log(
            f"TCP complete: {len(self.tcp_passed_configs)}/{len(configs)} passed "
            f"({passed_pct:.1f}%) in {elapsed_phase1:.1f}s"
        )

        if not self.tcp_passed_configs:
            _log("No configs passed TCP precheck")
            self.save_results()
            return 0

        if self._deadline_reached():
            _log("\nDeadline reached before xray phase - saving partial results")
            self.stopped_early = True
            self.save_results()
            return 0

        _log("\nPhase 2: Xray validation")
        _log("-" * 60)
        start_phase2 = time.time()
        self._run_xray_validation(self.tcp_passed_configs)
        elapsed_phase2 = time.time() - start_phase2
        self.phase2_seconds = elapsed_phase2

        self.working_configs.sort(key=lambda item: item[1])
        self.save_results()

        _log("\n" + "=" * 60)
        _log(f"Fetched: {len(configs)}")
        _log(f"TCP passed: {len(self.tcp_passed_configs)}")
        _log(f"Xray verified: {len(self.working_configs)}")
        _log(f"Phase 1: {elapsed_phase1:.1f}s | Phase 2: {elapsed_phase2:.1f}s")
        if self.stopped_early:
            _log(f"Stopped early at the {self.deadline_seconds}s budget - partial results saved")
        _log(f"Results: {self.output_file}")
        _log("=" * 60)

        if self.working_configs:
            _log("\nTop 10:")
            for index, (config, latency) in enumerate(self.working_configs[:10], 1):
                _log(f"  {index}. [{config.protocol.upper()}] {config.name[:40]} - {latency:.0f}ms")

        return 0

    def has_working_configs(self) -> bool:
        return bool(self.working_configs)

    def _run_tcp_precheck(self, configs: List[ProxyConfig]) -> List[ProxyConfig]:
        passed: List[ProxyConfig] = []
        total = len(configs)
        stopped_early = False

        executor = ThreadPoolExecutor(max_workers=self.max_workers)
        try:
            futures = {executor.submit(self._test_tcp, config): config for config in configs}

            for index, future in enumerate(as_completed(futures), 1):
                try:
                    result = future.result()
                    if result is not None:
                        passed.append(result)
                except Exception:
                    pass

                if index % 500 == 0 or index == total:
                    _log(f"  TCP progress: {index}/{total} ({len(passed)} passed)")

                if index != total and self._deadline_reached():
                    stopped_early = True
                    break
        finally:
            if stopped_early:
                executor.shutdown(wait=False, cancel_futures=True)
            else:
                executor.shutdown(wait=True)

        if stopped_early:
            self.stopped_early = True
            _log("  Deadline reached - TCP phase stopped early")
        return passed

    def _test_tcp(self, config: ProxyConfig) -> Optional[ProxyConfig]:
        success, _ = self.tcp_checker.test_config_tcp(config)
        return config if success else None

    def _run_xray_validation(self, configs: List[ProxyConfig]) -> None:
        total = len(configs)
        stopped_early = False

        executor = ThreadPoolExecutor(max_workers=self.xray_workers)
        try:
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

                if index % 100 == 0 or index == total:
                    with self.lock:
                        working = len(self.working_configs)
                    _log(f"  Xray progress: {index}/{total} ({working} working)")

                if index != total and self._deadline_reached():
                    stopped_early = True
                    break
        finally:
            if stopped_early:
                executor.shutdown(wait=False, cancel_futures=True)
            else:
                executor.shutdown(wait=True)

        if stopped_early:
            self.stopped_early = True
            _log("  Deadline reached - xray phase stopped early")

    def _test_xray(self, config: ProxyConfig) -> Tuple[bool, float]:
        try:
            return self.xray_validator.test_config_with_xray(config)
        except Exception:
            return False, -1.0

    def save_results(self) -> None:
        with open(self.output_file, 'w', encoding='utf-8') as handle:
            handle.write("# V2Ray Config Checker Results\n")
            handle.write(f"# Generated: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}\n")
            handle.write(f"# Fetched configs: {self.total_fetched}\n")
            handle.write(f"# TCP passed: {len(self.tcp_passed_configs)}\n")
            handle.write(f"# Working configs: {len(self.working_configs)}\n")
            handle.write(f"# Phase 1 (TCP): {self.phase1_seconds:.1f}s\n")
            handle.write(f"# Phase 2 (Xray): {self.phase2_seconds:.1f}s\n")
            if self.stopped_early:
                handle.write(f"# Partial run: stopped at the {self.deadline_seconds}s budget\n")
            handle.write("#" + "=" * 50 + "\n\n")

            for config, _ in self.working_configs:
                handle.write(f"{config.raw_config}\n")


def main() -> None:
    bot = ConfigCheckerBot()
    raise SystemExit(bot.run())


if __name__ == "__main__":
    main()
