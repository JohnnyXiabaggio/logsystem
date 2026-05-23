"""System-wide configuration loaded from environment + YAML file."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

try:
    import yaml
    _YAML_AVAILABLE = True
except ImportError:
    _YAML_AVAILABLE = False


@dataclass
class CollectorConfig:
    watch_paths: list[str] = field(default_factory=list)
    poll_interval_sec: float = 1.0
    include_system_metrics: bool = True
    metrics_interval_sec: float = 30.0
    source_label: str = "logsystem"


@dataclass
class BufferConfig:
    max_size: int = 10_000
    flush_interval_sec: float = 5.0
    flush_batch_size: int = 500


@dataclass
class UploaderConfig:
    endpoint_url: str = ""
    api_key: str = ""
    timeout_sec: float = 10.0
    retry_attempts: int = 4
    retry_backoff_sec: float = 2.0
    max_batch_size: int = 500
    # Dry-run: log batches locally instead of sending
    dry_run: bool = False


@dataclass
class MonitorConfig:
    error_rate_threshold: float = 0.10      # fraction of ERROR+ events to trigger alert
    error_rate_window_sec: float = 60.0
    critical_burst_threshold: int = 5        # CRITICAL events in window
    critical_burst_window_sec: float = 30.0
    alert_cooldown_sec: float = 300.0        # suppress repeat alerts
    alert_endpoint_url: str = ""             # where to POST alerts
    alert_api_key: str = ""


@dataclass
class LogSystemConfig:
    collector: CollectorConfig = field(default_factory=CollectorConfig)
    buffer: BufferConfig = field(default_factory=BufferConfig)
    uploader: UploaderConfig = field(default_factory=UploaderConfig)
    monitor: MonitorConfig = field(default_factory=MonitorConfig)
    log_level: str = "INFO"

    @classmethod
    def from_file(cls, path: str | Path) -> "LogSystemConfig":
        path = Path(path)
        if not path.exists():
            return cls()

        if not _YAML_AVAILABLE:
            raise RuntimeError("PyYAML is required to load config files: pip install pyyaml")

        with open(path) as f:
            raw: dict[str, Any] = yaml.safe_load(f) or {}

        cfg = cls()
        if "collector" in raw:
            c = raw["collector"]
            cfg.collector = CollectorConfig(
                watch_paths=c.get("watch_paths", []),
                poll_interval_sec=c.get("poll_interval_sec", 1.0),
                include_system_metrics=c.get("include_system_metrics", True),
                metrics_interval_sec=c.get("metrics_interval_sec", 30.0),
                source_label=c.get("source_label", "logsystem"),
            )
        if "buffer" in raw:
            b = raw["buffer"]
            cfg.buffer = BufferConfig(
                max_size=b.get("max_size", 10_000),
                flush_interval_sec=b.get("flush_interval_sec", 5.0),
                flush_batch_size=b.get("flush_batch_size", 500),
            )
        if "uploader" in raw:
            u = raw["uploader"]
            cfg.uploader = UploaderConfig(
                endpoint_url=u.get("endpoint_url", ""),
                api_key=u.get("api_key", ""),
                timeout_sec=u.get("timeout_sec", 10.0),
                retry_attempts=u.get("retry_attempts", 4),
                retry_backoff_sec=u.get("retry_backoff_sec", 2.0),
                max_batch_size=u.get("max_batch_size", 500),
                dry_run=u.get("dry_run", False),
            )
        if "monitor" in raw:
            m = raw["monitor"]
            cfg.monitor = MonitorConfig(
                error_rate_threshold=m.get("error_rate_threshold", 0.10),
                error_rate_window_sec=m.get("error_rate_window_sec", 60.0),
                critical_burst_threshold=m.get("critical_burst_threshold", 5),
                critical_burst_window_sec=m.get("critical_burst_window_sec", 30.0),
                alert_cooldown_sec=m.get("alert_cooldown_sec", 300.0),
                alert_endpoint_url=m.get("alert_endpoint_url", ""),
                alert_api_key=m.get("alert_api_key", ""),
            )
        cfg.log_level = raw.get("log_level", "INFO")
        return cfg

    @classmethod
    def from_env(cls) -> "LogSystemConfig":
        """Override config values from environment variables."""
        cfg = cls()
        cfg.uploader.endpoint_url = os.environ.get("LOGSYS_ENDPOINT", cfg.uploader.endpoint_url)
        cfg.uploader.api_key = os.environ.get("LOGSYS_API_KEY", cfg.uploader.api_key)
        cfg.uploader.dry_run = os.environ.get("LOGSYS_DRY_RUN", "").lower() in ("1", "true", "yes")
        cfg.monitor.alert_endpoint_url = os.environ.get("LOGSYS_ALERT_ENDPOINT", cfg.monitor.alert_endpoint_url)
        cfg.monitor.alert_api_key = os.environ.get("LOGSYS_ALERT_API_KEY", cfg.monitor.alert_api_key)
        return cfg
