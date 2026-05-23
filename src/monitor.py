"""Cloud issue monitor: detects anomalies in the event stream and fires alerts."""

from __future__ import annotations

import json
import logging
import threading
import time
import urllib.error
import urllib.request
from collections import deque
from datetime import datetime, timezone

from .models import LogEvent, Severity, Alert
from .config import MonitorConfig

logger = logging.getLogger(__name__)


class IssueMonitor:
    """
    Inspects every event flowing through the pipeline (call `observe(event)`).

    Detects:
    - High error rate: fraction of ERROR+ events exceeds threshold in a rolling window
    - Critical burst: N or more CRITICAL events in a short window

    On detection, fires an Alert and POSTs it to the configured alert endpoint.
    A cooldown prevents alert storms.
    """

    def __init__(self, cfg: MonitorConfig) -> None:
        self._cfg = cfg
        self._lock = threading.Lock()

        # Rolling windows store (timestamp, severity_code) tuples
        self._error_window: deque[tuple[float, int]] = deque()
        self._critical_window: deque[float] = deque()

        # Cooldown tracking per alert type; -inf means "never alerted"
        self._last_alert: dict[str, float] = {}

        self._alerts_fired = 0
        self._events_observed = 0

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def observe(self, event: LogEvent) -> None:
        now = time.monotonic()
        with self._lock:
            self._events_observed += 1
            self._record_event(event, now)
            alerts = self._check_rules(now)

        for alert in alerts:
            self._fire_alert(alert)

    @property
    def stats(self) -> dict:
        with self._lock:
            return {
                "events_observed": self._events_observed,
                "alerts_fired": self._alerts_fired,
            }

    # ------------------------------------------------------------------
    # Internal — must be called with self._lock held
    # ------------------------------------------------------------------

    def _record_event(self, event: LogEvent, now: float) -> None:
        self._error_window.append((now, int(event.severity)))
        if event.severity >= Severity.CRITICAL:
            self._critical_window.append(now)

        # Purge stale entries from windows
        error_cutoff = now - self._cfg.error_rate_window_sec
        while self._error_window and self._error_window[0][0] < error_cutoff:
            self._error_window.popleft()

        critical_cutoff = now - self._cfg.critical_burst_window_sec
        while self._critical_window and self._critical_window[0] < critical_cutoff:
            self._critical_window.popleft()

    def _check_rules(self, now: float) -> list[Alert]:
        alerts: list[Alert] = []

        # Rule 1: High error rate
        total = len(self._error_window)
        if total >= 10:  # need minimum sample
            error_count = sum(1 for _, s in self._error_window if s >= Severity.ERROR)
            rate = error_count / total
            if rate >= self._cfg.error_rate_threshold and self._can_alert("high_error_rate", now):
                alerts.append(Alert(
                    title="High Error Rate Detected",
                    description=(
                        f"Error rate {rate:.1%} exceeds threshold {self._cfg.error_rate_threshold:.1%} "
                        f"over the last {self._cfg.error_rate_window_sec:.0f}s "
                        f"({error_count}/{total} events)."
                    ),
                    severity=Severity.ERROR,
                    source="monitor/error-rate",
                    context={"error_rate": rate, "error_count": error_count, "total_events": total},
                ))

        # Rule 2: Critical burst
        burst_count = len(self._critical_window)
        if burst_count >= self._cfg.critical_burst_threshold and self._can_alert("critical_burst", now):
            alerts.append(Alert(
                title="Critical Event Burst",
                description=(
                    f"{burst_count} CRITICAL events in the last "
                    f"{self._cfg.critical_burst_window_sec:.0f}s — "
                    f"threshold is {self._cfg.critical_burst_threshold}."
                ),
                severity=Severity.CRITICAL,
                source="monitor/critical-burst",
                context={"burst_count": burst_count},
            ))

        return alerts

    def _can_alert(self, key: str, now: float) -> bool:
        last = self._last_alert.get(key, -float("inf"))
        if now - last >= self._cfg.alert_cooldown_sec:
            self._last_alert[key] = now
            self._alerts_fired += 1
            return True
        return False

    # ------------------------------------------------------------------
    # Alert dispatch (no lock held)
    # ------------------------------------------------------------------

    def _fire_alert(self, alert: Alert) -> None:
        logger.warning(
            "ALERT [%s] %s — %s",
            alert.severity.label(),
            alert.title,
            alert.description,
        )
        if self._cfg.alert_endpoint_url:
            self._post_alert(alert)

    def _post_alert(self, alert: Alert) -> None:
        body = json.dumps(alert.to_dict()).encode("utf-8")
        req = urllib.request.Request(
            self._cfg.alert_endpoint_url,
            data=body,
            method="POST",
            headers={
                "Content-Type": "application/json",
                "User-Agent": "logsystem/1.0",
                **({"Authorization": f"Bearer {self._cfg.alert_api_key}"} if self._cfg.alert_api_key else {}),
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                logger.info("Alert %s posted (HTTP %d)", alert.alert_id[:8], resp.status)
        except (urllib.error.URLError, OSError) as exc:
            logger.error("Failed to post alert %s: %s", alert.alert_id[:8], exc)


class PipelineHealthMonitor:
    """
    Periodically logs pipeline health stats (buffer, uploader, monitor).
    Runs in a background daemon thread.
    """

    def __init__(self, interval_sec: float = 60.0) -> None:
        self._interval = interval_sec
        self._providers: dict[str, object] = {}
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def register(self, name: str, provider: object) -> None:
        """Register any object with a .stats property."""
        self._providers[name] = provider

    def start(self) -> None:
        self._thread = threading.Thread(
            target=self._loop,
            name="health-monitor",
            daemon=True,
        )
        self._thread.start()
        logger.info("PipelineHealthMonitor started (interval=%.0fs)", self._interval)

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5)

    def _loop(self) -> None:
        while not self._stop.wait(timeout=self._interval):
            self._report()

    def _report(self) -> None:
        report: dict = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "components": {},
        }
        for name, provider in self._providers.items():
            try:
                report["components"][name] = provider.stats  # type: ignore[attr-defined]
            except Exception:
                report["components"][name] = "error"
        logger.info("Pipeline health: %s", json.dumps(report))
