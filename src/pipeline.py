"""Orchestrates collector → buffer → uploader → monitor."""

from __future__ import annotations

import logging
import signal
import sys
from pathlib import Path

from .config import LogSystemConfig, CollectorConfig
from .buffer import EventBuffer
from .collector import FileTailCollector, StdinCollector, SystemMetricsCollector
from .monitor import IssueMonitor, PipelineHealthMonitor
from .models import LogEvent
from .uploader import CloudUploader

logger = logging.getLogger(__name__)


class Pipeline:
    """
    Top-level object that wires all components together.

    Usage:
        pipeline = Pipeline(cfg)
        pipeline.start()
        pipeline.run_until_signal()   # blocks until SIGINT/SIGTERM
        pipeline.stop()
    """

    def __init__(self, cfg: LogSystemConfig) -> None:
        self._cfg = cfg

        self._uploader = CloudUploader(cfg.uploader)
        self._monitor = IssueMonitor(cfg.monitor)
        self._buffer = EventBuffer(cfg.buffer, on_flush=self._uploader.upload_batch)

        self._file_collector: FileTailCollector | None = None
        self._stdin_collector: StdinCollector | None = None
        self._metrics_collector: SystemMetricsCollector | None = None

        self._health = PipelineHealthMonitor(interval_sec=60.0)
        self._health.register("buffer", self._buffer)
        self._health.register("uploader", self._uploader)
        self._health.register("monitor", self._monitor)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def emit(self, event: LogEvent) -> None:
        """Inject a single event directly into the pipeline (for SDK use)."""
        self._monitor.observe(event)
        self._buffer.put(event)

    def start(self) -> None:
        logger.info("Starting log pipeline")
        self._buffer.start()

        col_cfg = self._cfg.collector
        if col_cfg.watch_paths:
            self._file_collector = FileTailCollector(
                col_cfg.watch_paths, col_cfg, sink=self.emit
            )
            self._file_collector.start()

        if self._cfg.collector.include_system_metrics:
            self._metrics_collector = SystemMetricsCollector(col_cfg, sink=self.emit)
            self._metrics_collector.start()

        self._health.start()
        logger.info("Pipeline started")

    def start_stdin(self) -> None:
        """Also attach a stdin collector (call after start())."""
        self._stdin_collector = StdinCollector(self._cfg.collector, sink=self.emit)
        self._stdin_collector.start()

    def stop(self) -> None:
        logger.info("Stopping pipeline")
        for col in (self._file_collector, self._stdin_collector, self._metrics_collector):
            if col:
                col.stop()
        self._health.stop()
        self._buffer.stop()  # drains remaining events
        logger.info(
            "Pipeline stopped | buffer=%s | uploader=%s | monitor=%s",
            self._buffer.stats,
            self._uploader.stats,
            self._monitor.stats,
        )

    def run_until_signal(self) -> None:
        """Block the main thread until SIGINT or SIGTERM is received."""
        stop_event = __import__("threading").Event()

        def _handle(signum, frame):
            logger.info("Signal %d received — shutting down", signum)
            stop_event.set()

        signal.signal(signal.SIGINT, _handle)
        signal.signal(signal.SIGTERM, _handle)
        stop_event.wait()
