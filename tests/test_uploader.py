"""Tests for CloudUploader."""

from unittest.mock import patch, MagicMock
import urllib.error
import urllib.request

from src.uploader import CloudUploader
from src.config import UploaderConfig
from src.models import LogEvent, Severity


def make_uploader(**kwargs) -> CloudUploader:
    cfg = UploaderConfig(
        endpoint_url=kwargs.get("endpoint_url", "http://example.com/logs"),
        api_key=kwargs.get("api_key", "test-key"),
        timeout_sec=5.0,
        retry_attempts=kwargs.get("retry_attempts", 2),
        retry_backoff_sec=0.01,
        max_batch_size=kwargs.get("max_batch_size", 100),
        dry_run=kwargs.get("dry_run", False),
    )
    return CloudUploader(cfg)


class TestDryRun:
    def test_dry_run_does_not_make_network_call(self):
        uploader = make_uploader(dry_run=True)
        events = [LogEvent(message="test")]
        with patch("urllib.request.urlopen") as mock_open:
            uploader.upload_batch(events)
            mock_open.assert_not_called()
        assert uploader.stats["total_events_sent"] == 1

    def test_no_endpoint_treated_as_dry_run(self):
        uploader = make_uploader(endpoint_url="", dry_run=False)
        events = [LogEvent(message="test")]
        with patch("urllib.request.urlopen") as mock_open:
            uploader.upload_batch(events)
            mock_open.assert_not_called()
        assert uploader.stats["total_events_sent"] == 1


class TestRetry:
    def test_retries_on_server_error_then_succeeds(self):
        uploader = make_uploader(retry_attempts=3)
        events = [LogEvent(message="test")]
        call_count = 0

        def fake_open(req, timeout):
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise urllib.error.HTTPError(url=None, code=503, msg="Service Unavailable", hdrs=None, fp=None)
            mock_resp = MagicMock()
            mock_resp.status = 200
            mock_resp.__enter__ = lambda s: s
            mock_resp.__exit__ = MagicMock(return_value=False)
            return mock_resp

        with patch("urllib.request.urlopen", side_effect=fake_open):
            uploader.upload_batch(events)

        assert uploader.stats["total_events_sent"] == 1
        assert call_count == 3

    def test_gives_up_after_max_retries(self):
        uploader = make_uploader(retry_attempts=2)
        events = [LogEvent(message="test")]

        def always_fail(req, timeout):
            raise urllib.error.HTTPError(url=None, code=500, msg="Error", hdrs=None, fp=None)

        with patch("urllib.request.urlopen", side_effect=always_fail):
            uploader.upload_batch(events)

        assert uploader.stats["total_events_failed"] == 1
        assert uploader.stats["total_events_sent"] == 0

    def test_no_retry_on_4xx(self):
        uploader = make_uploader(retry_attempts=3)
        events = [LogEvent(message="test")]
        call_count = 0

        def client_error(req, timeout):
            nonlocal call_count
            call_count += 1
            raise urllib.error.HTTPError(url=None, code=400, msg="Bad Request", hdrs=None, fp=None)

        with patch("urllib.request.urlopen", side_effect=client_error):
            uploader.upload_batch(events)

        assert call_count == 1  # no retry on 4xx

    def test_splits_large_batch(self):
        uploader = make_uploader(max_batch_size=3, dry_run=True)
        events = [LogEvent(message=f"msg {i}") for i in range(7)]
        uploader.upload_batch(events)
        assert uploader.stats["total_batches"] == 3  # ceil(7/3)
        assert uploader.stats["total_events_sent"] == 7
