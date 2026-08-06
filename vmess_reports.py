# -*- coding: utf-8 -*-
from __future__ import annotations

import hashlib
import json
import os
import re
import statistics
import tempfile
import threading
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from vmess_types import AppError, LinkResult, clean_text


def sanitize_network_name(value: str) -> str:
    original = clean_text(value)
    if not original:
        raise AppError("network-name cannot be empty")
    chars: List[str] = []
    for char in original:
        if char.isspace():
            chars.append("_")
        elif char.isalnum() or char in {"_", "-"}:
            chars.append(char)
    safe = re.sub(r"_+", "_", "".join(chars)).strip("_-")
    if not safe:
        raise AppError("network-name contains no valid filename characters")
    return safe[:80]


def calculate_input_set_sha256(links: Iterable[str]) -> str:
    payload = "\n".join(sorted(set(links))).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def generate_run_timestamp(now: Optional[datetime] = None) -> str:
    return (now or datetime.now().astimezone()).strftime("%Y%m%d_%H%M%S")


@dataclass(frozen=True)
class RunPaths:
    output_dir: Path
    accepted_txt: Path
    report_txt: Path
    report_json: Path
    history_txt: Path


def create_run_paths(output_root: Path, network_name: str, timestamp: str) -> RunPaths:
    if not re.fullmatch(r"\d{8}_\d{6}", timestamp):
        raise AppError("timestamp must use YYYYMMDD_HHMMSS format")
    safe_name = sanitize_network_name(network_name)
    run_dir = output_root.expanduser() / safe_name
    return RunPaths(
        output_dir=run_dir,
        accepted_txt=run_dir / f"{timestamp}_accepted_vmess.txt",
        report_txt=run_dir / f"{timestamp}_report.txt",
        report_json=run_dir / f"{timestamp}_report.json",
        history_txt=output_root.expanduser() / "test_history.txt",
    )


def atomic_write_text(path: Path, text: str, encoding: str = "utf-8") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = path.with_name(path.name + f".{os.getpid()}.{threading.get_ident()}.tmp")
    try:
        with temp_path.open("w", encoding=encoding, newline="\n") as file_obj:
            file_obj.write(text)
            file_obj.flush()
            os.fsync(file_obj.fileno())
        os.replace(str(temp_path), str(path))
    except OSError as exc:
        raise AppError(f"cannot write output file {path}: {exc}") from exc
    finally:
        try:
            temp_path.unlink()
        except FileNotFoundError:
            pass


def _format_latency(value: Optional[float]) -> str:
    return "-" if value is None else f"{value:.0f} ms"


def _normalize_failure_stage(stage: str) -> str:
    mapping = {
        "parse": "parse", "validation": "validation", "startup": "startup",
        "request": "request", "end-to-end": "request", "worker": "unexpected",
        "xray-execution": "unexpected",
    }
    return mapping.get(stage, "unexpected")


def _redact_error_text(value: str) -> str:
    text = clean_text(value).replace("\r", " ").replace("\n", " ")
    roots = {str(Path.home()), tempfile.gettempdir()}
    for root in sorted((item for item in roots if item), key=len, reverse=True):
        text = text.replace(root, "[PATH]")
        text = text.replace(root.replace("\\", "/"), "[PATH]")
    text = re.sub(r"(?i)(token|authorization|bearer)\s*[:=]\s*\S+",
                  r"\1=[REDACTED]", text)
    return text[:1200] or "-"


def render_text_report(accepted_exported: Sequence[LinkResult],
                       all_results: Sequence[LinkResult],
                       metadata: Dict[str, object], redact_links: bool) -> str:
    parse_failures = [item for item in all_results if item.error_stage == "parse"]
    tested = [item for item in all_results if item.error_stage != "parse"]
    accepted_all = [item for item in tested if item.accepted]
    rejected = [item for item in tested if not item.accepted]
    latencies = [float(item.median_latency_ms) for item in accepted_all
                 if item.median_latency_ms is not None]
    median_accepted = statistics.median(latencies) if latencies else None
    acceptance_rate = len(accepted_all) / len(tested) * 100.0 if tested else 0.0
    scores = [item.score for item in accepted_all]
    stage_counts = {name: 0 for name in ("parse", "validation", "startup", "request", "unexpected")}
    for item in all_results:
        if not item.accepted:
            stage_counts[_normalize_failure_stage(item.error_stage)] += 1

    lines = [
        "VMess End-to-End Test Report", "=" * 60, "", "Run information", "---------------",
        f"Network name: {metadata.get('network_name', '-')}",
        f"Profile: {metadata.get('profile', '-')}",
        f"Date and local time: {metadata.get('generated_at_local', '-')}",
        f"UTC time: {metadata.get('generated_at_utc', '-')}",
        f"Python version: {metadata.get('python_version', '-')}",
        f"Xray version: {metadata.get('xray_version', '-')}",
        f"Operating system: {metadata.get('operating_system', '-')}",
        "Test URLs: " + ", ".join(str(item) for item in metadata.get("test_urls", [])),
        f"Workers: {metadata.get('workers', '-')}",
        f"Attempts: {metadata.get('attempts', '-')}",
        f"Request timeout: {metadata.get('request_timeout', '-')} s",
        f"Startup timeout: {metadata.get('startup_timeout', '-')} s",
        f"Minimum score: {metadata.get('min_score', '-')}",
        f"Source mode: {metadata.get('source_mode', '-')}",
        f"Seed file: {metadata.get('seed_file', '-')}",
        f"Sample size requested: {metadata.get('sample_requested', 0)}",
        f"Input link count: {metadata.get('input_link_count', 0)}",
        f"Input set SHA-256: {metadata.get('input_set_sha256', '-')}",
        "", "Summary", "-------",
        f"Collected: {metadata.get('raw_links', 0)}",
        f"Parsed: {metadata.get('unique_configs', 0)}",
        f"Parse failures: {len(parse_failures)}", f"Tested: {len(tested)}",
        f"Accepted: {len(accepted_all)}", f"Exported accepted: {len(accepted_exported)}",
        f"Rejected: {len(rejected)}", f"Acceptance rate: {acceptance_rate:.1f}%",
        f"Median accepted latency: {_format_latency(median_accepted)}",
        f"Best score: {max(scores) if scores else '-'}",
        f"Worst accepted score: {min(scores) if scores else '-'}",
        "", "Failure stages", "--------------",
        f"parse: {stage_counts['parse']}", f"validation: {stage_counts['validation']}",
        f"startup: {stage_counts['startup']}", f"request: {stage_counts['request']}",
        f"unexpected: {stage_counts['unexpected']}",
        "", "Accepted configurations", "-----------------------",
    ]
    if not accepted_exported:
        lines.append("None")
    else:
        for index, item in enumerate(accepted_exported, 1):
            lines.extend([
                f"{index:02d}. Score: {item.score}",
                f"    Success rate: {item.success_rate * 100.0:.1f}%",
                f"    Median latency: {_format_latency(item.median_latency_ms)}",
                f"    Transport: {item.network or '-'}",
                f"    Security: {item.transport_security or '-'}",
                f"    Remark: {item.remark or '-'}", "    Server: [REDACTED]",
                f"    Link: {'[REDACTED]' if redact_links else item.link}", "",
            ])
    lines.extend(["Rejected configurations", "-----------------------"])
    failed = [item for item in all_results if not item.accepted]
    if not failed:
        lines.append("None")
    else:
        for index, item in enumerate(failed, 1):
            lines.extend([
                f"{index:02d}. Score: {item.score}",
                f"    Failure stage: {_normalize_failure_stage(item.error_stage)}",
                f"    Error: {_redact_error_text(item.error)}",
                f"    Transport: {item.network or '-'}",
                f"    Security: {item.transport_security or '-'}",
                f"    Remark: {item.remark or '-'}", "    Server: [REDACTED]", "",
            ])
    return "\n".join(lines).rstrip() + "\n"


def _lock(file_obj) -> None:
    if os.name == "nt":
        import msvcrt
        file_obj.seek(0)
        msvcrt.locking(file_obj.fileno(), msvcrt.LK_LOCK, 1)
    else:
        import fcntl
        fcntl.flock(file_obj.fileno(), fcntl.LOCK_EX)


def _unlock(file_obj) -> None:
    if os.name == "nt":
        import msvcrt
        file_obj.seek(0)
        msvcrt.locking(file_obj.fileno(), msvcrt.LK_UNLCK, 1)
    else:
        import fcntl
        fcntl.flock(file_obj.fileno(), fcntl.LOCK_UN)


def append_history(history_path: Path, line: str) -> None:
    history_path.parent.mkdir(parents=True, exist_ok=True)
    lock_path = history_path.with_name(".test_history.lock")
    try:
        with lock_path.open("a+b") as lock_file:
            lock_file.seek(0, os.SEEK_END)
            if lock_file.tell() == 0:
                lock_file.write(b"0")
                lock_file.flush()
            _lock(lock_file)
            try:
                with history_path.open("a+b") as history_file:
                    history_file.seek(0, os.SEEK_END)
                    if history_file.tell() == 0:
                        history_file.write(b"\xef\xbb\xbf")
                    history_file.write((line.rstrip("\n") + "\n").encode("utf-8"))
                    history_file.flush()
                    os.fsync(history_file.fileno())
            finally:
                _unlock(lock_file)
    except OSError as exc:
        raise AppError(f"cannot append history file {history_path}: {exc}") from exc


def write_outputs(output_root: Path, network_name: str, timestamp: str,
                  accepted: Sequence[LinkResult], all_results: Sequence[LinkResult],
                  metadata: Dict[str, object], redact_links_in_report: bool = False
                  ) -> Tuple[Path, Path, Path, Path]:
    paths = create_run_paths(output_root, network_name, timestamp)
    targets = (paths.accepted_txt, paths.report_txt, paths.report_json)
    existing = [str(path) for path in targets if path.exists()]
    if existing:
        raise AppError("output files already exist; refusing to overwrite: " + ", ".join(existing))
    pure_links = "\n".join(item.link for item in accepted)
    if pure_links:
        pure_links += "\n"
    payload = {
        "metadata": metadata,
        "accepted_count": len(accepted),
        "tested_count": len([item for item in all_results if item.error_stage != "parse"]),
        "accepted": [item.to_dict() for item in accepted],
        "all_results": [item.to_dict() for item in all_results],
    }
    atomic_write_text(paths.accepted_txt, pure_links, "utf-8")
    atomic_write_text(paths.report_txt,
                      render_text_report(accepted, all_results, metadata, redact_links_in_report),
                      "utf-8-sig")
    atomic_write_text(paths.report_json, json.dumps(payload, ensure_ascii=False, indent=2) + "\n")

    tested = [item for item in all_results if item.error_stage != "parse"]
    accepted_all = [item for item in tested if item.accepted]
    latencies = [float(item.median_latency_ms) for item in accepted_all
                 if item.median_latency_ms is not None]
    median = f"{statistics.median(latencies):.0f}ms" if latencies else "-"
    rate = len(accepted_all) / len(tested) * 100.0 if tested else 0.0
    history_line = (
        f"{metadata.get('generated_at_local', '-')} | {metadata.get('network_name', network_name)} | "
        f"input_hash={metadata.get('input_set_sha256', '-')} | tested={len(tested)} | "
        f"accepted={len(accepted_all)} | acceptance={rate:.1f}% | median={median}"
    )
    append_history(paths.history_txt, history_line)
    return paths.accepted_txt, paths.report_txt, paths.report_json, paths.history_txt
