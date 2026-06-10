#!/usr/bin/env python3
"""CLI entry point for the log system."""

from __future__ import annotations

import argparse
import logging
import os
import sys
from pathlib import Path

# Allow running as `python main.py` from repo root
sys.path.insert(0, str(Path(__file__).parent))

from src import LogSystemConfig, Pipeline
from src.config import CollectorConfig, BufferConfig, UploaderConfig, MonitorConfig


def build_config(args: argparse.Namespace) -> LogSystemConfig:
    cfg = LogSystemConfig()

    # Load from file if provided
    if args.config and Path(args.config).exists():
        cfg = LogSystemConfig.from_file(args.config)

    # CLI flags override file config
    if args.watch:
        cfg.collector.watch_paths = args.watch
    if args.endpoint:
        cfg.uploader.endpoint_url = args.endpoint
    if args.api_key:
        cfg.uploader.api_key = args.api_key
    if args.dry_run:
        cfg.uploader.dry_run = True
    if args.no_metrics:
        cfg.collector.include_system_metrics = False

    # Environment overrides (highest priority)
    env_endpoint = os.environ.get("LOGSYS_ENDPOINT")
    if env_endpoint:
        cfg.uploader.endpoint_url = env_endpoint
    env_key = os.environ.get("LOGSYS_API_KEY")
    if env_key:
        cfg.uploader.api_key = env_key
    if os.environ.get("LOGSYS_DRY_RUN", "").lower() in ("1", "true", "yes"):
        cfg.uploader.dry_run = True

    return cfg


def setup_logging(level: str) -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)-8s %(name)s — %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
        stream=sys.stderr,
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="logsystem — collect, upload, and monitor log events in real time",
    )
    parser.add_argument(
        "-c", "--config",
        metavar="FILE",
        default="config/logsystem.yaml",
        help="path to YAML config file (default: config/logsystem.yaml)",
    )
    parser.add_argument(
        "-w", "--watch",
        metavar="PATH",
        nargs="+",
        help="log file paths to tail",
    )
    parser.add_argument(
        "--stdin",
        action="store_true",
        help="also read events from stdin (JSON or plain text, one per line)",
    )
    parser.add_argument(
        "--endpoint",
        metavar="URL",
        help="cloud endpoint URL to upload events to",
    )
    parser.add_argument(
        "--api-key",
        metavar="KEY",
        help="API key for the cloud endpoint",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="log batches locally instead of uploading",
    )
    parser.add_argument(
        "--no-metrics",
        action="store_true",
        help="disable system metrics collection",
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="internal log verbosity (default: INFO)",
    )
    args = parser.parse_args()

    setup_logging(args.log_level)
    cfg = build_config(args)

    pipeline = Pipeline(cfg)
    pipeline.start()

    if args.stdin:
        pipeline.start_stdin()

    try:
        pipeline.run_until_signal()
    finally:
        pipeline.stop()


if __name__ == "__main__":
    main()
