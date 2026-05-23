"""Cloud uploader with batching, retry with exponential backoff, and dry-run support."""

from __future__ import annotations

import json
import logging
import time
import urllib.error
import urllib.request
from typing import Any

from .models import LogEvent, UploadBatch
from .config import UploaderConfig

logger = logging.getLogger(__name__)


class CloudUploader:
    """
    Receives batches of LogEvents from the buffer flush callback and sends
    them to a configured HTTP endpoint.

    Retry strategy: exponential backoff up to `retry_attempts` times.
    In dry_run mode, payloads are written to the local logger instead.
    """

    def __init__(self, cfg: UploaderConfig) -> None:
        self._cfg = cfg
        self._total_sent = 0
        self._total_failed = 0
        self._total_batches = 0

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def upload_batch(self, events: list[LogEvent]) -> None:
        """Called by EventBuffer on flush; batches are split to max_batch_size."""
        for i in range(0, max(1, len(events)), self._cfg.max_batch_size):
            chunk = events[i : i + self._cfg.max_batch_size]
            batch = UploadBatch(events=chunk)
            self._send_with_retry(batch)

    @property
    def stats(self) -> dict:
        return {
            "total_batches": self._total_batches,
            "total_events_sent": self._total_sent,
            "total_events_failed": self._total_failed,
        }

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _send_with_retry(self, batch: UploadBatch) -> None:
        self._total_batches += 1
        delay = self._cfg.retry_backoff_sec

        for attempt in range(1, self._cfg.retry_attempts + 1):
            try:
                self._send(batch)
                self._total_sent += len(batch.events)
                logger.debug(
                    "Batch %s uploaded (%d events, attempt %d)",
                    batch.batch_id[:8],
                    len(batch.events),
                    attempt,
                )
                return
            except _RetryableError as exc:
                if attempt == self._cfg.retry_attempts:
                    logger.error(
                        "Batch %s failed after %d attempts: %s",
                        batch.batch_id[:8],
                        attempt,
                        exc,
                    )
                    self._total_failed += len(batch.events)
                    return
                logger.warning(
                    "Batch %s upload attempt %d failed (%s) — retrying in %.1fs",
                    batch.batch_id[:8],
                    attempt,
                    exc,
                    delay,
                )
                time.sleep(delay)
                delay *= 2
            except _FatalError as exc:
                logger.error("Batch %s fatal upload error: %s", batch.batch_id[:8], exc)
                self._total_failed += len(batch.events)
                return

    def _send(self, batch: UploadBatch) -> None:
        payload = batch.to_payload()

        if self._cfg.dry_run or not self._cfg.endpoint_url:
            logger.info(
                "[DRY-RUN] Would upload batch %s with %d events to %s",
                batch.batch_id[:8],
                len(batch.events),
                self._cfg.endpoint_url or "(no endpoint)",
            )
            if logger.isEnabledFor(logging.DEBUG):
                logger.debug("Payload: %s", json.dumps(payload, indent=2))
            return

        body = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            self._cfg.endpoint_url,
            data=body,
            method="POST",
            headers={
                "Content-Type": "application/json",
                "User-Agent": "logsystem/1.0",
                **({"Authorization": f"Bearer {self._cfg.api_key}"} if self._cfg.api_key else {}),
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=self._cfg.timeout_sec) as resp:
                status = resp.status
        except urllib.error.HTTPError as exc:
            status = exc.code
            if status in (429, 500, 502, 503, 504):
                raise _RetryableError(f"HTTP {status}") from exc
            raise _FatalError(f"HTTP {status}") from exc
        except (urllib.error.URLError, OSError) as exc:
            raise _RetryableError(str(exc)) from exc

        if status >= 400:
            raise _FatalError(f"Unexpected HTTP {status}")


class _RetryableError(Exception):
    pass


class _FatalError(Exception):
    pass
