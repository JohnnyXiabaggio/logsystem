# logsystem

Real-time log event collection, cloud upload, and issue monitoring in Python.

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                         Pipeline                             │
│                                                              │
│  ┌──────────────┐   put()   ┌───────────────────────────┐   │
│  │  Collectors  │──────────▶│       EventBuffer          │   │
│  │              │           │  (thread-safe, timed flush)│   │
│  │ • FileTail   │           └────────────┬──────────────┘   │
│  │ • Stdin      │                        │ on_flush()        │
│  │ • SysMetrics │           ┌────────────▼──────────────┐   │
│  └──────────────┘           │      CloudUploader         │   │
│         │                   │  (batch, retry, backoff)   │   │
│         │ observe()         └───────────────────────────┘   │
│         ▼                                                    │
│  ┌──────────────┐           ┌───────────────────────────┐   │
│  │ IssueMonitor │──alerts──▶│    Alert Endpoint (HTTP)   │   │
│  │              │           └───────────────────────────┘   │
│  └──────────────┘                                            │
│         │                                                    │
│  ┌──────────────┐                                            │
│  │HealthMonitor │  (logs pipeline stats every 60s)           │
│  └──────────────┘                                            │
└──────────────────────────────────────────────────────────────┘
```

## Components

| Module | Responsibility |
|---|---|
| `src/models.py` | `LogEvent`, `UploadBatch`, `Alert` dataclasses + `Severity` enum |
| `src/config.py` | YAML + environment variable configuration |
| `src/collector.py` | File tail, stdin, and system-metrics collectors |
| `src/buffer.py` | Thread-safe in-memory queue; flushes on interval or batch size |
| `src/uploader.py` | HTTP POST to cloud endpoint with exponential-backoff retry |
| `src/monitor.py` | Rolling-window anomaly detection; POSTs alerts to a webhook |
| `src/pipeline.py` | Wires everything together; handles SIGINT/SIGTERM gracefully |
| `main.py` | CLI entry point |

## Quick start

```bash
pip install -r requirements.txt

# Dry run — no network calls, just logs what would be uploaded
python main.py --dry-run --watch /var/log/app.log

# Point at a real cloud endpoint
LOGSYS_ENDPOINT=https://ingest.example.com/logs \
LOGSYS_API_KEY=mytoken \
python main.py --watch /var/log/app.log /var/log/syslog

# Read from stdin (pipe-friendly)
tail -F /var/log/app.log | python main.py --stdin --dry-run
```

## Configuration

Edit `config/logsystem.yaml` or set environment variables:

| Env var | Purpose |
|---|---|
| `LOGSYS_ENDPOINT` | Cloud ingest URL |
| `LOGSYS_API_KEY` | Bearer token for ingest endpoint |
| `LOGSYS_DRY_RUN` | `1` to log locally instead of uploading |
| `LOGSYS_ALERT_ENDPOINT` | Webhook URL for monitor alerts |
| `LOGSYS_ALERT_API_KEY` | Bearer token for alert webhook |

### Key settings

```yaml
buffer:
  flush_interval_sec: 5.0   # upload at least every 5 seconds
  flush_batch_size: 500     # also upload when 500 events accumulate
  max_size: 10000           # drop events when queue exceeds this

uploader:
  retry_attempts: 4         # exponential backoff: 2s, 4s, 8s, 16s

monitor:
  error_rate_threshold: 0.10      # alert if >10% events are ERROR+
  critical_burst_threshold: 5     # alert if 5 CRITICALs in 30s
  alert_cooldown_sec: 300.0       # suppress duplicate alerts for 5 min
```

## Event format

Events are uploaded as JSON batches:

```json
{
  "batch_id": "uuid",
  "created_at": "2026-05-23T10:00:00+00:00",
  "event_count": 2,
  "events": [
    {
      "event_id": "uuid",
      "timestamp": "2026-05-23T10:00:00+00:00",
      "severity": "ERROR",
      "severity_code": 40,
      "source": "/var/log/app.log",
      "message": "connection timeout",
      "tags": {},
      "extra": {}
    }
  ]
}
```

Input lines can be **plain text** (severity auto-detected from keywords `CRITICAL/ERROR/WARNING/DEBUG`) or **structured JSON** with `message`, `level`/`severity`, `source`, and `tags` fields.

## SDK usage

```python
from src import LogSystemConfig, Pipeline, LogEvent, Severity

cfg = LogSystemConfig.from_file("config/logsystem.yaml")
pipeline = Pipeline(cfg)
pipeline.start()

pipeline.emit(LogEvent(
    message="user login failed",
    severity=Severity.WARNING,
    source="auth-service",
    tags={"env": "prod"},
))

pipeline.stop()
```

## Tests

```bash
pytest tests/ -v
```

33 tests covering models, buffer, collectors, uploader (with mock HTTP), and monitor.
