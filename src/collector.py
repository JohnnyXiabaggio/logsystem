"""Event collectors: file tail, stdin, system metrics."""

from __future__ import annotations

import io
import json
import logging
import os
import platform
import re
import threading
import time
from pathlib import Path
from typing import Callable

from .models import LogEvent, Severity
from .config import CollectorConfig

logger = logging.getLogger(__name__)

EventSink = Callable[[LogEvent], None]

# Regex patterns to auto-detect severity in plain text log lines
_SEVERITY_PATTERNS: list[tuple[re.Pattern, Severity]] = [
    (re.compile(r"\b(CRITICAL|FATAL)\b", re.IGNORECASE), Severity.CRITICAL),
    (re.compile(r"\bERROR\b", re.IGNORECASE), Severity.ERROR),
    (re.compile(r"\bWARN(ING)?\b", re.IGNORECASE), Severity.WARNING),
    (re.compile(r"\bDEBUG\b", re.IGNORECASE), Severity.DEBUG),
]


def _detect_severity(line: str) -> Severity:
    for pattern, severity in _SEVERITY_PATTERNS:
        if pattern.search(line):
            return severity
    return Severity.INFO


def _parse_line(line: str, source: str) -> LogEvent | None:
    line = line.strip()
    if not line:
        return None
    # Try JSON first
    if line.startswith("{"):
        try:
            d = json.loads(line)
            return LogEvent(
                message=d.get("message", d.get("msg", line)),
                severity=Severity.from_string(d.get("level", d.get("severity", "INFO"))),
                source=d.get("source", source),
                tags=d.get("tags", {}),
                extra={k: v for k, v in d.items() if k not in ("message", "msg", "level", "severity", "source", "tags")},
            )
        except (json.JSONDecodeError, KeyError):
            pass
    return LogEvent(
        message=line,
        severity=_detect_severity(line),
        source=source,
    )


class FileTailCollector:
    """
    Tails one or more log files, emitting a LogEvent per new line.
    Handles log rotation by re-opening the file when it shrinks.
    """

    def __init__(self, paths: list[str], cfg: CollectorConfig, sink: EventSink) -> None:
        self._paths = [Path(p) for p in paths]
        self._cfg = cfg
        self._sink = sink
        self._stop = threading.Event()
        self._threads: list[threading.Thread] = []

    def start(self) -> None:
        for path in self._paths:
            t = threading.Thread(
                target=self._tail,
                args=(path,),
                name=f"tail-{path.name}",
                daemon=True,
            )
            t.start()
            self._threads.append(t)
            logger.info("FileTailCollector watching %s", path)

    def stop(self) -> None:
        self._stop.set()
        for t in self._threads:
            t.join(timeout=5)

    def _tail(self, path: Path) -> None:
        file: io.TextIOWrapper | None = None
        pos = 0
        while not self._stop.is_set():
            try:
                if not path.exists():
                    time.sleep(self._cfg.poll_interval_sec)
                    continue

                current_size = path.stat().st_size

                if file is None:
                    file = open(path, "r", errors="replace")
                    file.seek(0, 2)  # seek to end on first open
                    pos = file.tell()
                elif current_size < pos:
                    # File was rotated / truncated
                    logger.info("Log rotation detected for %s, reopening", path)
                    file.close()
                    file = open(path, "r", errors="replace")
                    pos = 0

                file.seek(pos)
                for raw_line in file:
                    event = _parse_line(raw_line, source=str(path))
                    if event:
                        self._sink(event)
                pos = file.tell()

            except OSError:
                logger.exception("Error reading %s", path)
                if file:
                    file.close()
                    file = None

            time.sleep(self._cfg.poll_interval_sec)

        if file:
            file.close()


class StdinCollector:
    """Reads log lines from stdin (useful for pipe-based ingestion)."""

    def __init__(self, cfg: CollectorConfig, sink: EventSink) -> None:
        self._cfg = cfg
        self._sink = sink
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        self._thread = threading.Thread(
            target=self._read_stdin,
            name="stdin-collector",
            daemon=True,
        )
        self._thread.start()
        logger.info("StdinCollector started")

    def stop(self) -> None:
        self._stop.set()

    def _read_stdin(self) -> None:
        import sys
        for raw_line in sys.stdin:
            if self._stop.is_set():
                break
            event = _parse_line(raw_line, source="stdin")
            if event:
                self._sink(event)


class SystemMetricsCollector:
    """
    Periodically samples CPU, memory, and disk usage and emits metric events.
    Requires the 'psutil' package; degrades gracefully if unavailable.
    """

    def __init__(self, cfg: CollectorConfig, sink: EventSink) -> None:
        self._cfg = cfg
        self._sink = sink
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._available = self._check_psutil()

    @staticmethod
    def _check_psutil() -> bool:
        try:
            import psutil  # noqa: F401
            return True
        except ImportError:
            logger.warning("psutil not installed — system metrics collection disabled")
            return False

    def start(self) -> None:
        if not self._available:
            return
        self._thread = threading.Thread(
            target=self._collect_loop,
            name="metrics-collector",
            daemon=True,
        )
        self._thread.start()
        logger.info("SystemMetricsCollector started (interval=%.1fs)", self._cfg.metrics_interval_sec)

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5)

    def _collect_loop(self) -> None:
        import psutil
        while not self._stop.wait(timeout=self._cfg.metrics_interval_sec):
            try:
                cpu = psutil.cpu_percent(interval=1)
                mem = psutil.virtual_memory()
                disk = psutil.disk_usage("/")

                severity = Severity.INFO
                messages = []
                if cpu > 90:
                    severity = max(severity, Severity.WARNING)
                    messages.append(f"High CPU: {cpu:.1f}%")
                if mem.percent > 85:
                    severity = max(severity, Severity.WARNING)
                    messages.append(f"High memory: {mem.percent:.1f}%")
                if disk.percent > 90:
                    severity = max(severity, Severity.ERROR)
                    messages.append(f"Disk critical: {disk.percent:.1f}%")

                message = "; ".join(messages) if messages else "System metrics OK"
                event = LogEvent(
                    message=message,
                    severity=severity,
                    source="system-metrics",
                    tags={"host": platform.node()},
                    extra={
                        "cpu_percent": cpu,
                        "mem_percent": mem.percent,
                        "mem_available_mb": mem.available // (1024 * 1024),
                        "disk_percent": disk.percent,
                        "disk_free_gb": disk.free // (1024 ** 3),
                    },
                )
                self._sink(event)
            except Exception:
                logger.exception("Error collecting system metrics")
