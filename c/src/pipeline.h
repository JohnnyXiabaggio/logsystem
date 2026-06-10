/**
 * @file pipeline.h
 * @brief Top-level orchestration: collector → (monitor at ingest) →
 *        ring buffer → flush thread → uploader.
 *
 * Latency model ("get the issue in time"):
 *   - Issue DETECTION happens in pipeline_emit, at ingest — alert
 *     latency is microseconds and independent of flush cadence or
 *     upload health.
 *   - Issue DELIVERY: events with severity >= ERROR wake the flush
 *     thread immediately (rb wake policy); routine traffic is batched
 *     on flush_interval_ms.
 *   - The flush thread drains until the ring is empty on every wake —
 *     sustained throughput is bounded by upload bandwidth, not by the
 *     flush interval.
 */

#ifndef PIPELINE_H
#define PIPELINE_H

#include "logsys_types.h"
#include "ring_buffer.h"
#include "collector.h"
#include "uploader.h"
#include "monitor.h"
#include <pthread.h>

#define FLUSH_BATCH (200U)

typedef struct {
    RingBuffer  rb;
    Collector   collector;
    Uploader    uploader;
    Monitor     monitor;

    pthread_t       flush_thread;
    pthread_t       health_thread;
    volatile bool_t running;
    bool_t          flush_started;
    bool_t          health_started;

    uint32_t flush_interval_ms;
    uint32_t health_interval_ms;
} Pipeline;

LogSysErr pipeline_init(Pipeline *p);
LogSysErr pipeline_start(Pipeline *p);
LogSysErr pipeline_stop(Pipeline *p);
LogSysErr pipeline_destroy(Pipeline *p);

/**
 * Inject one event: observed by the monitor immediately (issue
 * detection at ingest), then queued for upload.
 * @return rb_push result (LOGSYS_ERR_FULL = dropped by backpressure).
 */
LogSysErr pipeline_emit(Pipeline *p, const LogEvent *e);

/** Block until SIGINT/SIGTERM (sigaction-based). */
LogSysErr pipeline_run_until_signal(Pipeline *p);

#endif /* PIPELINE_H */
