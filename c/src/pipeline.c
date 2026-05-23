#include "pipeline.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <time.h>
#include <inttypes.h>
#include <pthread.h>

#define RB_CAPACITY 10000

/* ------------------------------------------------------------------ */
/* Flush thread — drains ring buffer, monitors, uploads                */
/* ------------------------------------------------------------------ */

static void *flush_thread(void *arg) {
    Pipeline *p = (Pipeline *)arg;
    LogEvent batch[FLUSH_BATCH];

    while (p->running) {
        struct timespec ts = {
            .tv_sec  = (time_t)p->flush_interval_sec,
            .tv_nsec = (long)((p->flush_interval_sec -
                               (time_t)p->flush_interval_sec) * 1e9)
        };
        nanosleep(&ts, NULL);

        size_t n = rb_drain(&p->rb, batch, FLUSH_BATCH);
        if (n == 0) continue;

        /* Pass each event through the monitor before uploading */
        for (size_t i = 0; i < n; i++)
            monitor_observe(&p->monitor, &batch[i]);

        uploader_send(&p->uploader, batch, n);
    }

    /* Final drain on shutdown */
    size_t n;
    while ((n = rb_drain(&p->rb, batch, FLUSH_BATCH)) > 0) {
        for (size_t i = 0; i < n; i++)
            monitor_observe(&p->monitor, &batch[i]);
        uploader_send(&p->uploader, batch, n);
    }
    return NULL;
}

/* ------------------------------------------------------------------ */
/* Health-report thread                                                */
/* ------------------------------------------------------------------ */

static void *health_thread(void *arg) {
    Pipeline *p = (Pipeline *)arg;
    while (p->running) {
        struct timespec ts = {
            .tv_sec  = (time_t)p->health_interval_sec,
            .tv_nsec = 0
        };
        nanosleep(&ts, NULL);

        size_t queued; uint64_t rb_in, rb_out; size_t dropped;
        rb_stats(&p->rb, &queued, &rb_in, &rb_out, &dropped);

        uint64_t ev_obs, alerts;
        monitor_stats(&p->monitor, &ev_obs, &alerts);

        fprintf(stderr,
            "[health] buffer(queued=%zu in=%" PRIu64 " out=%" PRIu64
            " dropped=%zu) "
            "uploader(batches=%" PRIu64 " sent=%" PRIu64 " failed=%" PRIu64 ") "
            "monitor(observed=%" PRIu64 " alerts=%" PRIu64 ")\n",
            queued, rb_in, rb_out, dropped,
            p->uploader.total_batches, p->uploader.total_sent,
            p->uploader.total_failed,
            ev_obs, alerts);
    }
    return NULL;
}

/* ------------------------------------------------------------------ */
/* Signal handling                                                     */
/* ------------------------------------------------------------------ */

static volatile sig_atomic_t g_stop = 0;

static void sig_handler(int sig) {
    (void)sig;
    g_stop = 1;
}

/* ------------------------------------------------------------------ */
/* Public API                                                          */
/* ------------------------------------------------------------------ */

int pipeline_init(Pipeline *p) {
    memset(p, 0, sizeof(*p));
    p->flush_interval_sec  = 5.0;
    p->health_interval_sec = 60.0;

    if (rb_init(&p->rb, RB_CAPACITY) < 0) return -1;
    collector_init(&p->collector, &p->rb, 1000 /* poll_ms */);
    uploader_init(&p->uploader);
    monitor_init(&p->monitor);
    return 0;
}

void pipeline_start(Pipeline *p) {
    p->running = 1;
    collector_start(&p->collector);
    pthread_create(&p->flush_thread,  NULL, flush_thread,  p);
    pthread_create(&p->health_thread, NULL, health_thread, p);
    fprintf(stderr, "[pipeline] started\n");
}

void pipeline_stop(Pipeline *p) {
    fprintf(stderr, "[pipeline] shutting down\n");
    collector_stop(&p->collector);
    p->running = 0;
    pthread_join(p->flush_thread,  NULL);
    pthread_join(p->health_thread, NULL);

    /* Final stats */
    size_t queued; uint64_t rb_in, rb_out; size_t dropped;
    rb_stats(&p->rb, &queued, &rb_in, &rb_out, &dropped);
    fprintf(stderr,
        "[pipeline] stopped | buffer(in=%" PRIu64 " out=%" PRIu64
        " dropped=%zu) "
        "uploader(sent=%" PRIu64 " failed=%" PRIu64 ")\n",
        rb_in, rb_out, dropped,
        p->uploader.total_sent, p->uploader.total_failed);
}

void pipeline_free(Pipeline *p) {
    rb_destroy(&p->rb);
    collector_free(&p->collector);
}

void pipeline_run_until_signal(Pipeline *p) {
    (void)p;
    signal(SIGINT,  sig_handler);
    signal(SIGTERM, sig_handler);
    fprintf(stderr, "[pipeline] running — press Ctrl+C to stop\n");
    while (!g_stop) {
        struct timespec ts = { .tv_sec = 0, .tv_nsec = 100000000L }; /* 100ms */
        nanosleep(&ts, NULL);
    }
}
