/**
 * @file pipeline.h
 * @brief Top-level orchestration: collector → buffer → uploader + monitor.
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

/** Block until SIGINT/SIGTERM is delivered.  Uses sigaction (POSIX,
 *  safer than ANSI signal). */
LogSysErr pipeline_run_until_signal(Pipeline *p);

#endif /* PIPELINE_H */
