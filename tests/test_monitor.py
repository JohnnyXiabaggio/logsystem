"""Tests for IssueMonitor."""

import time

from src.monitor import IssueMonitor
from src.config import MonitorConfig
from src.models import LogEvent, Severity


def make_monitor(**kwargs) -> IssueMonitor:
    cfg = MonitorConfig(
        error_rate_threshold=kwargs.get("error_rate_threshold", 0.5),
        error_rate_window_sec=kwargs.get("error_rate_window_sec", 10.0),
        critical_burst_threshold=kwargs.get("critical_burst_threshold", 3),
        critical_burst_window_sec=kwargs.get("critical_burst_window_sec", 10.0),
        alert_cooldown_sec=kwargs.get("alert_cooldown_sec", 0.0),
        alert_endpoint_url="",
    )
    return IssueMonitor(cfg)


class TestIssueMonitor:
    def test_no_alert_below_threshold(self):
        mon = make_monitor(error_rate_threshold=0.5)
        for _ in range(20):
            mon.observe(LogEvent(message="ok", severity=Severity.INFO))
        # Only 1 error in 21 events — well below 50%
        mon.observe(LogEvent(message="err", severity=Severity.ERROR))
        assert mon.stats["alerts_fired"] == 0

    def test_high_error_rate_alert(self):
        mon = make_monitor(error_rate_threshold=0.5, alert_cooldown_sec=0)
        # Send 10 INFO then 10 ERROR to exceed 50% threshold with >=10 samples
        for _ in range(5):
            mon.observe(LogEvent(message="ok", severity=Severity.INFO))
        for _ in range(10):
            mon.observe(LogEvent(message="err", severity=Severity.ERROR))
        assert mon.stats["alerts_fired"] >= 1

    def test_critical_burst_alert(self):
        mon = make_monitor(critical_burst_threshold=3, alert_cooldown_sec=0)
        for _ in range(3):
            mon.observe(LogEvent(message="BOOM", severity=Severity.CRITICAL))
        assert mon.stats["alerts_fired"] >= 1

    def test_alert_cooldown_suppresses_repeat(self):
        mon = make_monitor(
            critical_burst_threshold=3,
            alert_cooldown_sec=9999.0,  # very long cooldown
        )
        for _ in range(6):
            mon.observe(LogEvent(message="BOOM", severity=Severity.CRITICAL))
        # Should only fire once despite multiple threshold crossings
        assert mon.stats["alerts_fired"] == 1

    def test_stats_counts_events(self):
        mon = make_monitor()
        for i in range(10):
            mon.observe(LogEvent(message=f"msg {i}"))
        assert mon.stats["events_observed"] == 10

    def test_old_events_expire_from_window(self):
        # Use a very short window
        mon = make_monitor(
            critical_burst_threshold=3,
            critical_burst_window_sec=0.1,
            alert_cooldown_sec=0,
        )
        for _ in range(3):
            mon.observe(LogEvent(message="BOOM", severity=Severity.CRITICAL))
        time.sleep(0.2)  # let the window expire
        # Reset cooldown by observing with a fresh monitor — verify new events needed
        alerts_after_expiry = mon.stats["alerts_fired"]
        # Now add more criticals; they should NOT re-trigger because previous ones expired
        mon.observe(LogEvent(message="BOOM", severity=Severity.CRITICAL))
        # Only 1 event in window now — below threshold of 3
        # alerts_fired should not increase
        assert mon.stats["alerts_fired"] == alerts_after_expiry
