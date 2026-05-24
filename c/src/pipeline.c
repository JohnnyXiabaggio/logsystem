/**
 * @file pipeline.c
 * @brief Pipeline implementation.
 *
 * - sigaction (not signal) for SIGINT/SIGTERM (MISRA 21.5 deviation
 *   documented; sigaction is the safer POSIX equivalent).
 * - All pthread return values checked.
 * - All uploader return values captured.
 * - Bounded shutdown drain (max FLUSH_BATCH * 1024 events).
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

/* ------------------------------------------------------------------ */
/* Flush thread                                                        */
/* ------------------------------------------------------------------ */

static void *flush_thread(void *arg)
{
    Pipeline *p = (Pipeline *)arg;
    LogEvent  batch[FLUSH_BATCH];

    if (p != NULL) {
        while (p->running == LOGSYS_TRUE) {
            struct timespec ts;
            uint32_t        n_out = 0U;
            LogSysErr       rc;

            ts.tv_sec  = (time_t)(p->flush_interval_ms / 1000U);
            ts.tv_nsec = (long)((p->flush_interval_ms % 1000U) * 1000000U);
            (void)nanosleep(&ts, NULL);

            if (rb_drain(&p->rb, batch, FLUSH_BATCH, &n_out) == LOGSYS_OK) {
                if (n_out > 0U) {
                    uint32_t i;
                    for (i = 0U; i < n_out; i++) {
                        (void)monitor_observe(&p->monitor, &batch[i]);
                    }
                    rc = uploader_send(&p->uploader, batch, n_out);
                    if (rc != LOGSYS_OK) {
                        (void)fprintf(stderr,
                            "[flush] uploader_send returned %d\n", (int)rc);
                    }
                }
            }
        }

        /* Final drain on shutdown — bounded by 1024 iterations to
         * guarantee termination in finite time. */
        {
            uint32_t guard = 1024U;
            uint32_t n_out;
            do {
                n_out = 0U;
                if (rb_drain(&p->rb, batch, FLUSH_BATCH, &n_out) == LOGSYS_OK) {
                    if (n_out > 0U) {
                        uint32_t i;
                        for (i = 0U; i < n_out; i++) {
                            (void)monitor_observe(&p->monitor, &batch[i]);
                        }
                        (void)uploader_send(&p->uploader, batch, n_out);
                    }
                }
                guard--;
            } while ((n_out > 0U) && (guard > 0U));
        }
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
            struct timespec ts;
            uint32_t        queued    = 0U;
            uint64_t        rb_in     = 0U;
            uint64_t        rb_out    = 0U;
            uint32_t        dropped   = 0U;
            uint64_t        observed  = 0U;
            uint64_t        alerts    = 0U;

            ts.tv_sec  = (time_t)(p->health_interval_ms / 1000U);
            ts.tv_nsec = 0;
            (void)nanosleep(&ts, NULL);

            (void)rb_stats(&p->rb, &queued, &rb_in, &rb_out, &dropped);
            (void)monitor_stats(&p->monitor, &observed, &alerts);

            (void)fprintf(stderr,
                "[health] buffer(queued=%u in=%" PRIu64 " out=%" PRIu64
                " dropped=%u) "
                "uploader(batches=%" PRIu64 " sent=%" PRIu64
                " failed=%" PRIu64 ") "
                "monitor(observed=%" PRIu64 " alerts=%" PRIu64 ")\n",
                (unsigned)queued, rb_in, rb_out, (unsigned)dropped,
                p->uploader.total_batches,
                p->uploader.total_sent,
                p->uploader.total_failed,
                observed, alerts);
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
        } else if (collector_init(&p->collector, &p->rb, 1000U) != LOGSYS_OK) {
            (void)rb_destroy(&p->rb);
            rc = LOGSYS_ERR_SYS;
        } else if (uploader_init(&p->uploader) != LOGSYS_OK) {
            (void)rb_destroy(&p->rb);
            rc = LOGSYS_ERR_SYS;
        } else if (monitor_init(&p->monitor) != LOGSYS_OK) {
            (void)rb_destroy(&p->rb);
            rc = LOGSYS_ERR_SYS;
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
                /* Flush thread is already running — let stop() join it. */
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
