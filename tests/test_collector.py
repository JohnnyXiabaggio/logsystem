"""Tests for collectors."""

import json
import tempfile
import time
from pathlib import Path

from src.collector import FileTailCollector, _parse_line, _detect_severity
from src.config import CollectorConfig
from src.models import LogEvent, Severity


def default_cfg() -> CollectorConfig:
    return CollectorConfig(poll_interval_sec=0.05)


class TestParseLine:
    def test_plain_info(self):
        e = _parse_line("application started", "test")
        assert e is not None
        assert e.severity == Severity.INFO
        assert e.message == "application started"

    def test_detects_error(self):
        e = _parse_line("2024-01-01 ERROR: disk full", "test")
        assert e.severity == Severity.ERROR

    def test_detects_warning(self):
        e = _parse_line("WARNING: low memory", "test")
        assert e.severity == Severity.WARNING

    def test_detects_critical(self):
        e = _parse_line("CRITICAL failure in subsystem", "test")
        assert e.severity == Severity.CRITICAL

    def test_json_line(self):
        payload = json.dumps({"message": "login", "level": "INFO", "user": "alice"})
        e = _parse_line(payload, "svc")
        assert e is not None
        assert e.message == "login"
        assert e.severity == Severity.INFO
        assert e.extra.get("user") == "alice"

    def test_empty_line(self):
        assert _parse_line("", "test") is None
        assert _parse_line("   ", "test") is None


class TestFileTailCollector:
    def test_tails_new_lines(self):
        collected: list[LogEvent] = []
        with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
            tmp_path = f.name
            f.write("first line\n")

        cfg = default_cfg()
        col = FileTailCollector([tmp_path], cfg, sink=collected.append)
        col.start()
        time.sleep(0.15)

        with open(tmp_path, "a") as f:
            f.write("second line\n")
            f.write("ERROR: something broke\n")

        time.sleep(0.3)
        col.stop()

        messages = [e.message for e in collected]
        assert "second line" in messages
        assert "ERROR: something broke" in messages

    def test_nonexistent_file_doesnt_crash(self):
        cfg = default_cfg()
        col = FileTailCollector(["/tmp/no_such_file_xyz.log"], cfg, sink=lambda e: None)
        col.start()
        time.sleep(0.15)
        col.stop()  # should not raise
