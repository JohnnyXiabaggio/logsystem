"""Core data models for the log system."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import IntEnum
from typing import Any


class Severity(IntEnum):
    DEBUG = 10
    INFO = 20
    WARNING = 30
    ERROR = 40
    CRITICAL = 50

    @classmethod
    def from_string(cls, s: str) -> "Severity":
        return cls[s.upper()]

    def label(self) -> str:
        return self.name


@dataclass
class LogEvent:
    message: str
    severity: Severity = Severity.INFO
    source: str = "unknown"
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    tags: dict[str, str] = field(default_factory=dict)
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp.isoformat(),
            "severity": self.severity.label(),
            "severity_code": int(self.severity),
            "source": self.source,
            "message": self.message,
            "tags": self.tags,
            "extra": self.extra,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "LogEvent":
        return cls(
            message=d["message"],
            severity=Severity[d.get("severity", "INFO")],
            source=d.get("source", "unknown"),
            timestamp=datetime.fromisoformat(d["timestamp"]) if "timestamp" in d else datetime.now(timezone.utc),
            event_id=d.get("event_id", str(uuid.uuid4())),
            tags=d.get("tags", {}),
            extra=d.get("extra", {}),
        )


@dataclass
class UploadBatch:
    events: list[LogEvent]
    batch_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_payload(self) -> dict[str, Any]:
        return {
            "batch_id": self.batch_id,
            "created_at": self.created_at.isoformat(),
            "event_count": len(self.events),
            "events": [e.to_dict() for e in self.events],
        }


@dataclass
class Alert:
    title: str
    description: str
    severity: Severity
    source: str
    triggered_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    alert_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    context: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "alert_id": self.alert_id,
            "triggered_at": self.triggered_at.isoformat(),
            "severity": self.severity.label(),
            "title": self.title,
            "description": self.description,
            "source": self.source,
            "context": self.context,
        }
