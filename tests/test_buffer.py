"""Tests for EventBuffer."""

import threading
import time

from src.buffer import EventBuffer
from src.config import BufferConfig
from src.models import LogEvent, Severity


def make_buffer(flush_interval=0.1, max_size=100, batch_size=10):
    received: list[list[LogEvent]] = []

    def on_flush(batch):
        received.append(list(batch))

    cfg = BufferConfig(
        max_size=max_size,
        flush_interval_sec=flush_interval,
        flush_batch_size=batch_size,
    )
    buf = EventBuffer(cfg, on_flush=on_flush)
    return buf, received


class TestEventBuffer:
    def test_timed_flush(self):
        buf, received = make_buffer(flush_interval=0.1)
        buf.start()
        for i in range(5):
            buf.put(LogEvent(message=f"msg {i}"))
        time.sleep(0.3)
        buf.stop()
        total = sum(len(b) for b in received)
        assert total == 5

    def test_batch_size_triggers_flush(self):
        buf, received = make_buffer(flush_interval=60, batch_size=3)
        buf.start()
        for i in range(6):
            buf.put(LogEvent(message=f"msg {i}"))
        time.sleep(0.1)
        buf.stop()
        total = sum(len(b) for b in received)
        assert total == 6

    def test_backpressure_drops_events(self):
        buf, received = make_buffer(max_size=5, flush_interval=60, batch_size=100)
        buf.start()
        results = [buf.put(LogEvent(message=f"msg {i}")) for i in range(10)]
        buf.stop()
        assert results[:5] == [True] * 5
        assert False in results[5:]
        assert buf.stats["dropped"] > 0

    def test_stats_accounting(self):
        buf, received = make_buffer(flush_interval=0.05)
        buf.start()
        for i in range(7):
            buf.put(LogEvent(message=f"msg {i}"))
        time.sleep(0.2)
        buf.stop()
        assert buf.stats["total_ingested"] == 7
        assert buf.stats["total_flushed"] == 7

    def test_thread_safety(self):
        buf, received = make_buffer(flush_interval=0.05, max_size=10_000)
        buf.start()
        N = 500

        def producer():
            for i in range(N):
                buf.put(LogEvent(message=f"msg {i}"))

        threads = [threading.Thread(target=producer) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        time.sleep(0.3)
        buf.stop()
        assert buf.stats["total_ingested"] == N * 4
