# -*- coding: utf-8 -*-
from __future__ import annotations

import concurrent.futures
import subprocess
import time
from collections import deque
from typing import Callable, Dict, Iterable, Optional, Tuple

from vmess_types import AppError, LinkResult, ProxyConfig
from vmess_xray import stop_all_processes


def _timed_test(test: Callable[[ProxyConfig], LinkResult],
                config: ProxyConfig) -> Tuple[LinkResult, float]:
    started = time.perf_counter()
    try:
        result = test(config)
    except (subprocess.SubprocessError, OSError, AppError, RuntimeError) as exc:
        result = LinkResult(
            config.dedup_key, config.raw, config.address, config.port,
            config.network, config.transport_security, config.remark,
            0, 0.0, None, False, "worker", f"{type(exc).__name__}: {exc}", [],
            protocol=config.protocol,
        )
    return result, time.perf_counter() - started


def run_tests(
    configs: Iterable[ProxyConfig],
    initial_test: Callable[[ProxyConfig], LinkResult],
    on_result: Callable[[ProxyConfig, LinkResult], None],
    workers: int,
    quality_test: Optional[Callable[[ProxyConfig], LinkResult]] = None,
    quality_workers: int = 2,
    logger: Callable[[str], None] = print,
) -> Tuple[bool, Dict[str, object]]:
    """Stream candidates between bounded pools; publish only final results.

    Without quality_test this runs the original single-stage workflow.
    A screening score never gates promotion: any successful HTTPS probe does.
    """
    if not 1 <= workers <= 16 or not 1 <= quality_workers <= 16:
        raise AppError("workers and quality-workers must be between 1 and 16")
    two_stage = quality_test is not None
    metrics: Dict[str, object] = {
        "screening_completed": 0, "quality_completed": 0,
        "quality_candidates": 0, "final_results": 0,
        "screening_worker_seconds": 0.0, "quality_worker_seconds": 0.0,
    }
    started = time.perf_counter()
    initial_pool = concurrent.futures.ThreadPoolExecutor(max_workers=workers)
    quality_pool = (concurrent.futures.ThreadPoolExecutor(max_workers=quality_workers)
                    if two_stage else None)
    pending = {}
    ready = deque()
    remaining = iter(configs)
    exhausted = False
    interrupted = False
    # Includes running futures and queued candidates, independent of input size.
    capacity = workers + quality_workers if two_stage else workers
    try:
        while not exhausted or pending or ready:
            quality_active = sum(stage == "quality" for _, stage in pending.values())
            while ready and quality_pool is not None and quality_active < quality_workers:
                config = ready.popleft()
                future = quality_pool.submit(_timed_test, quality_test, config)
                pending[future] = (config, "quality")
                quality_active += 1

            initial_active = sum(stage != "quality" for _, stage in pending.values())
            # In single-stage mode all futures belong to the initial pool.
            if not two_stage:
                initial_active = len(pending)
            while (not exhausted and initial_active < workers
                   and len(pending) + len(ready) < capacity):
                try:
                    config = next(remaining)
                except StopIteration:
                    exhausted = True
                    break
                future = initial_pool.submit(_timed_test, initial_test, config)
                pending[future] = (config, "screening" if two_stage else "quality")
                initial_active += 1

            if not pending:
                continue
            done, _ = concurrent.futures.wait(
                pending, timeout=0.5,
                return_when=concurrent.futures.FIRST_COMPLETED,
            )
            for future in done:
                config, stage = pending.pop(future)
                result, seconds = future.result()
                if result.error_stage == "cancelled":
                    continue
                metrics[stage + "_completed"] += 1
                metrics[stage + "_worker_seconds"] += seconds
                if stage == "screening" and any(probe.success for probe in result.probes):
                    ready.append(config)
                    metrics["quality_candidates"] += 1
                else:
                    # Never publish a screening-only result as accepted.
                    if stage == "screening":
                        result.accepted = False
                    metrics["final_results"] += 1
                    on_result(config, result)
    except KeyboardInterrupt:
        interrupted = True
        logger("\n[STOPPING] Interrupted by user; stopping Xray processes and saving partial results...")
    finally:
        # Also clean up workers when persistence or an unexpected task fails.
        if interrupted or pending or ready:
            stop_all_processes()
        initial_pool.shutdown(wait=True, cancel_futures=True)
        if quality_pool is not None:
            quality_pool.shutdown(wait=True, cancel_futures=True)
        elapsed = time.perf_counter() - started
        metrics["testing_elapsed_seconds"] = round(elapsed, 3)
        metrics["configs_per_minute"] = round(metrics["final_results"] * 60 / elapsed, 2) if elapsed else 0.0
        for name in ("screening_worker_seconds", "quality_worker_seconds"):
            metrics[name] = round(metrics[name], 3)
    return interrupted, metrics
