/**
 * @file pipeline.c
 * @brief Pipeline implementation.
 *
 * - Monitoring happens at ingest (pipeline_emit), not at flush.
 * - Flush thread: waits on the ring's urgent wake (or interval
 *   timeout), then drains until empty — no sustained-throughput
 *   ceiling from the flush cadence.
 * - The drain batch is a file-scope static (single flush thread), not
 *   a ~213 KB stack frame.
 * - sigaction for SIGINT/SIGTERM; all pthread returns checked.
 */

#include "pipeline.h"

#include <string.h>
#include <stdio.h>
#include <signal.h>
#include <time.h>
#include <inttypes.h>
#include <unistd.h>

/* Shutdown signal — set by sig_handler, polled by main thread. */
static volatile sig_atomic_t g_stop = 0;

static void sig_handler(int sig)
{
    LOGSYS_UNUSED(sig);
    g_stop = 1;
}

/* Drain staging area: owned exclusively by the flush thread.
 * Static, not stack — sizeof(LogEvent) * FLUSH_BATCH ≈ 213 KB. */
static LogEvent s_flush_batch[FLUSH_BATCH];

/* ------------------------------------------------------------------ */
/* Ingest path                                                         */
/* ------------------------------------------------------------------ */

LogSysErr pipeline_emit(Pipeline *p, const LogEvent *e)
{
    LogSysErr rc;

    if ((p == NULL) || (e == NULL)) {
        rc = LOGSYS_ERR_PARAM;
    } else {
        /* Detection first: an alert must fire even if the queue is
         * full and the event is subsequently dropped. */
        (void)monitor_observe(&p->monitor, e);
        rc = rb_push(&p->rb, e);
    }
    return rc;
}

/* Collector sink trampoline. */
static LogSysErr emit_sink(void *ctx, const LogEvent *e)
{
    return pipeline_emit((Pipeline *)ctx, e);
}

/* ------------------------------------------------------------------ */
/* Flush thread                                                        */
/* ------------------------------------------------------------------ */

/* Drain the ring until empty.  Bounded: the ring holds at most
 * RB_CAPACITY events and producers can only re-fill it as fast as the
 * guard allows. */
static void drain_all(Pipeline *p)
{
    uint32_t guard = (RB_CAPACITY / FLUSH_BATCH) + 2U;
    uint32_t n_out;

    do {
        n_out = 0U;
        if (rb_drain(&p->rb, s_flush_batch, FLUSH_BATCH,
                     &n_out) == LOGSYS_OK) {
            if (n_out > 0U) {
                if (uploader_send(&p->uploader, s_flush_batch,
                                  n_out) != LOGSYS_OK) {
                    (void)fprintf(stderr,
                        "[flush] uploader_send failed for %u events\n",
                        (unsigned)n_out);
                }
            }
        }
        guard--;
    } while ((n_out == FLUSH_BATCH) && (guard > 0U));
}

static void *flush_thread(void *arg)
{
    Pipeline *p = (Pipeline *)arg;

    if (p != NULL) {
        while (p->running == LOGSYS_TRUE) {
            /* Wakes early for ERROR+ events or watermark occupancy;
             * otherwise times out at the batching interval. */
            (void)rb_wait_wake(&p->rb, p->flush_interval_ms);
            drain_all(p);
        }
        /* Final drain on shutdown. */
        drain_all(p);
    }
    return NULL;
}

/* ------------------------------------------------------------------ */
/* Health-report thread                                                */
/* ------------------------------------------------------------------ */

static void *health_thread(void *arg)
{
    Pipeline *p = (Pipeline *)arg;

    if (p != NULL) {
        while (p->running == LOGSYS_TRUE) {
            uint32_t queued    = 0U;
            uint64_t rb_in     = 0U;
            uint64_t rb_out    = 0U;
            uint32_t dropped   = 0U;
            uint64_t observed  = 0U;
            uint64_t alerts    = 0U;
            uint64_t alerts_failed = 0U;
            uint64_t lines_read = 0U;
            uint64_t lines_dropped = 0U;
            uint64_t lines_trunc = 0U;

            /* Interruptible interval sleep: 250 ms granularity so
             * shutdown does not stall for the full health interval. */
            {
                uint32_t remaining = p->health_interval_ms;
                while ((remaining > 0U) && (p->running == LOGSYS_TRUE)) {
                    struct timespec ts;
                    const uint32_t  step =
                        (remaining > 250U) ? 250U : remaining;
                    ts.tv_sec  = 0;
                    ts.tv_nsec = (long)(step * 1000000U);
                    (void)nanosleep(&ts, NULL);
                    remaining -= step;
                }
            }
            if (p->running == LOGSYS_FALSE) {
                break;
            }

            (void)rb_stats(&p->rb, &queued, &rb_in, &rb_out, &dropped);
            (void)monitor_stats(&p->monitor, &observed, &alerts,
                                &alerts_failed);
            (void)collector_stats(&p->collector, &lines_read,
                                  &lines_dropped, &lines_trunc);

            (void)fprintf(stderr,
                "[health] buffer(queued=%u in=%" PRIu64 " out=%" PRIu64
                " dropped=%u) "
                "collector(read=%" PRIu64 " dropped=%" PRIu64
                " truncated=%" PRIu64 ") "
                "uploader(batches=%" PRIu64 " sent=%" PRIu64
                " failed=%" PRIu64 ") "
                "monitor(observed=%" PRIu64 " alerts=%" PRIu64
                " alert_failures=%" PRIu64 ")\n",
                (unsigned)queued, rb_in, rb_out, (unsigned)dropped,
                lines_read, lines_dropped, lines_trunc,
                p->uploader.total_batches,
                p->uploader.total_sent,
                p->uploader.total_failed,
                observed, alerts, alerts_failed);
        }
    }
    return NULL;
}

/* ------------------------------------------------------------------ */
/* Public API                                                          */
/* ------------------------------------------------------------------ */

LogSysErr pipeline_init(Pipeline *p)
{
    LogSysErr rc = LOGSYS_OK;

    if (p == NULL) {
        rc = LOGSYS_ERR_PARAM;
    } else {
        (void)memset(p, 0, sizeof(*p));
        p->flush_interval_ms  = 5000U;
        p->health_interval_ms = 60000U;
        p->running            = LOGSYS_FALSE;
        p->flush_started      = LOGSYS_FALSE;
        p->health_started     = LOGSYS_FALSE;

        if (rb_init(&p->rb) != LOGSYS_OK) {
            rc = LOGSYS_ERR_SYS;
        } else if (collector_init(&p->collector, emit_sink, p,
                                   1000U) != LOGSYS_OK) {
            (void)rb_destroy(&p->rb);
            rc = LOGSYS_ERR_SYS;
        } else if (uploader_init(&p->uploader) != LOGSYS_OK) {
            (void)rb_destroy(&p->rb);
            rc = LOGSYS_ERR_SYS;
        } else if (monitor_init(&p->monitor) != LOGSYS_OK) {
            (void)rb_destroy(&p->rb);
            rc = LOGSYS_ERR_SYS;
        } else {
            /* all components initialised */
        }
    }
    return rc;
}

LogSysErr pipeline_start(Pipeline *p)
{
    LogSysErr rc = LOGSYS_OK;

    if (p == NULL) {
        rc = LOGSYS_ERR_PARAM;
    } else {
        p->running = LOGSYS_TRUE;

        if (collector_start(&p->collector) != LOGSYS_OK) {
            p->running = LOGSYS_FALSE;
            rc         = LOGSYS_ERR_SYS;
        } else if (pthread_create(&p->flush_thread, NULL,
                                   flush_thread, p) != 0) {
            (void)collector_stop(&p->collector);
            p->running = LOGSYS_FALSE;
            rc         = LOGSYS_ERR_SYS;
        } else {
            p->flush_started = LOGSYS_TRUE;
            if (pthread_create(&p->health_thread, NULL,
                                health_thread, p) != 0) {
                /* Flush thread runs — pipeline_stop will join it. */
                rc = LOGSYS_ERR_SYS;
            } else {
                p->health_started = LOGSYS_TRUE;
                (void)fprintf(stderr, "[pipeline] started\n");
            }
        }
    }
    return rc;
}

LogSysErr pipeline_stop(Pipeline *p)
{
    LogSysErr rc = LOGSYS_OK;

    if (p == NULL) {
        rc = LOGSYS_ERR_PARAM;
    } else {
        (void)fprintf(stderr, "[pipeline] shutting down\n");
        if (p->collector.thread_started == LOGSYS_TRUE) {
            (void)collector_stop(&p->collector);
        }
        p->running = LOGSYS_FALSE;
        if (p->flush_started == LOGSYS_TRUE) {
            /* Unblock the flush thread's timed wait so shutdown does
             * not stall for a full flush interval. */
            (void)rb_wake(&p->rb);
            (void)pthread_join(p->flush_thread, NULL);
            p->flush_started = LOGSYS_FALSE;
        }
        if (p->health_started == LOGSYS_TRUE) {
            (void)pthread_join(p->health_thread, NULL);
            p->health_started = LOGSYS_FALSE;
        }

        {
            uint32_t queued  = 0U;
            uint64_t rb_in   = 0U;
            uint64_t rb_out  = 0U;
            uint32_t dropped = 0U;
            (void)rb_stats(&p->rb, &queued, &rb_in, &rb_out, &dropped);
            (void)fprintf(stderr,
                "[pipeline] stopped | buffer(in=%" PRIu64
                " out=%" PRIu64 " dropped=%u) "
                "uploader(sent=%" PRIu64 " failed=%" PRIu64 ")\n",
                rb_in, rb_out, (unsigned)dropped,
                p->uploader.total_sent, p->uploader.total_failed);
        }
    }
    return rc;
}

LogSysErr pipeline_destroy(Pipeline *p)
{
    LogSysErr rc = LOGSYS_OK;

    if (p == NULL) {
        rc = LOGSYS_ERR_PARAM;
    } else {
        (void)monitor_destroy(&p->monitor);
        (void)rb_destroy(&p->rb);
        /* Wipe uploader's API key (CWE-316). */
        (void)memset(p->uploader.api_key, 0, sizeof(p->uploader.api_key));
    }
    return rc;
}

LogSysErr pipeline_run_until_signal(Pipeline *p)
{
    LogSysErr        rc = LOGSYS_OK;
    struct sigaction sa;

    LOGSYS_UNUSED(p);

    (void)memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sig_handler;
    (void)sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;

    if ((sigaction(SIGINT,  &sa, NULL) != 0) ||
        (sigaction(SIGTERM, &sa, NULL) != 0)) {
        rc = LOGSYS_ERR_SYS;
    } else {
        (void)fprintf(stderr, "[pipeline] running — Ctrl+C to stop\n");
        while (g_stop == 0) {
            struct timespec ts;
            ts.tv_sec  = 0;
            ts.tv_nsec = 100000000L;   /* 100 ms */
            (void)nanosleep(&ts, NULL);
        }
    }
    return rc;
}
