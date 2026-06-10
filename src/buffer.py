"""Thread-safe event buffer with timed flush and backpressure."""

from __future__ import annotations

import logging
import threading
import time
from collections import deque
from typing import Callable

from .models import LogEvent
from .config import BufferConfig

logger = logging.getLogger(__name__)


class EventBuffer:
    """
    Accepts events from multiple collector threads and drains them in
    batches to a registered flush callback on a fixed interval or when
    the batch size threshold is reached.
    """

    def __init__(
        self,
        cfg: BufferConfig,
        on_flush: Callable[[list[LogEvent]], None],
    ) -> None:
        self._cfg = cfg
        self._on_flush = on_flush
        self._queue: deque[LogEvent] = deque()
        self._lock = threading.Lock()
        self._dropped = 0
        self._total_ingested = 0
        self._total_flushed = 0
        self._flush_thread: threading.Thread | None = None
        self._stop_event = threading.Event()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def put(self, event: LogEvent) -> bool:
        """Add an event to the buffer. Returns False if buffer is full (dropped)."""
        with self._lock:
            if len(self._queue) >= self._cfg.max_size:
                self._dropped += 1
                logger.warning("Buffer full — event dropped (total dropped: %d)", self._dropped)
                return False
            self._queue.append(event)
            self._total_ingested += 1
            should_flush = len(self._queue) >= self._cfg.flush_batch_size
        if should_flush:
            self._flush()
        return True

    def start(self) -> None:
        self._stop_event.clear()
        self._flush_thread = threading.Thread(
            target=self._flush_loop,
            name="buffer-flush",
            daemon=True,
        )
        self._flush_thread.start()
        logger.info("EventBuffer started (flush_interval=%.1fs, max_size=%d)",
                    self._cfg.flush_interval_sec, self._cfg.max_size)

    def stop(self) -> None:
        self._stop_event.set()
        if self._flush_thread:
            self._flush_thread.join(timeout=10)
        # Final drain
        self._flush()
        logger.info("EventBuffer stopped (ingested=%d, flushed=%d, dropped=%d)",
                    self._total_ingested, self._total_flushed, self._dropped)

    @property
    def stats(self) -> dict:
        with self._lock:
            return {
                "queued": len(self._queue),
                "total_ingested": self._total_ingested,
                "total_flushed": self._total_flushed,
                "dropped": self._dropped,
            }

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _flush_loop(self) -> None:
        while not self._stop_event.wait(timeout=self._cfg.flush_interval_sec):
            self._flush()

    def _flush(self) -> None:
        batch: list[LogEvent] = []
        with self._lock:
            while self._queue and len(batch) < self._cfg.flush_batch_size:
                batch.append(self._queue.popleft())
            self._total_flushed += len(batch)

        if not batch:
            return

        try:
            self._on_flush(batch)
        except Exception:
            logger.exception("Flush callback raised an exception for batch of %d events", len(batch))
