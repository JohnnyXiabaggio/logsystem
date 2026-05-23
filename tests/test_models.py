"""Tests for data models."""

import json
from datetime import datetime, timezone

import pytest

from src.models import LogEvent, Severity, UploadBatch, Alert


class TestSeverity:
    def test_ordering(self):
        assert Severity.DEBUG < Severity.INFO < Severity.WARNING < Severity.ERROR < Severity.CRITICAL

    def test_from_string(self):
        assert Severity.from_string("error") == Severity.ERROR
        assert Severity.from_string("WARNING") == Severity.WARNING

    def test_from_string_invalid(self):
        with pytest.raises(KeyError):
            Severity.from_string("UNKNOWN")


class TestLogEvent:
    def test_defaults(self):
        e = LogEvent(message="hello")
        assert e.severity == Severity.INFO
        assert e.source == "unknown"
        assert e.event_id != ""
        assert e.timestamp.tzinfo is not None

    def test_to_dict_round_trip(self):
        e = LogEvent(message="test", severity=Severity.ERROR, source="app", tags={"env": "prod"})
        d = e.to_dict()
        assert d["message"] == "test"
        assert d["severity"] == "ERROR"
        assert d["source"] == "app"
        assert d["tags"] == {"env": "prod"}

    def test_from_dict(self):
        d = {
            "message": "from dict",
            "severity": "WARNING",
            "source": "svc",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_id": "abc-123",
            "tags": {},
            "extra": {"key": "val"},
        }
        e = LogEvent.from_dict(d)
        assert e.message == "from dict"
        assert e.severity == Severity.WARNING
        assert e.extra == {"key": "val"}


class TestUploadBatch:
    def test_payload_structure(self):
        events = [LogEvent(message=f"msg {i}") for i in range(3)]
        batch = UploadBatch(events=events)
        payload = batch.to_payload()
        assert payload["event_count"] == 3
        assert len(payload["events"]) == 3
        assert "batch_id" in payload
        assert "created_at" in payload


class TestAlert:
    def test_to_dict(self):
        a = Alert(
            title="High Error Rate",
            description="50% errors",
            severity=Severity.ERROR,
            source="monitor",
        )
        d = a.to_dict()
        assert d["title"] == "High Error Rate"
        assert d["severity"] == "ERROR"
        assert "alert_id" in d
