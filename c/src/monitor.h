/**
 * @file monitor.h
 * @brief Issue monitor: rolling-window anomaly detection + alerting.
 *
 * Designed to be called at INGEST time (pipeline_emit), so detection
 * latency is independent of flush cadence and upload health.
 *
 * Performance (ECU):
 *   - O(1) per event: running counters are maintained on window
 *     push/evict — no per-event scan of the window.
 *   - One window implementation, two instances (error rate window and
 *     critical-burst window).
 *
 * Concurrency:
 *   - All window state is mutated under m->mu.
 *   - Alert dispatch (network I/O) happens AFTER the lock is released;
 *     the alert payload and endpoint/key are snapshotted under the lock.
 */

#ifndef MONITOR_H
#define MONITOR_H

#include "logsys_types.h"
#include "log_event.h"
#include <pthread.h>

#define MON_URL_MAX  (512U)
#define MON_KEY_MAX  (256U)

typedef struct {
    double   ts;      /* seconds, CLOCK_MONOTONIC */
    Severity sev;
} WinEntry;

/** Circular event window with an O(1) high-severity counter. */
typedef struct {
    WinEntry e[MON_WIN_MAX];
    uint32_t head;
    uint32_t count;
    uint32_t hi_count;      /* entries with sev >= the window's bar */
    Severity bar;           /* severity bar counted by hi_count     */
} Window;

typedef struct {
    /* --- configuration --- */
    double   error_rate_threshold;       /* fraction in [0.0, 1.0] */
    double   error_rate_window_sec;
    uint32_t critical_burst_threshold;
    double   critical_burst_window_sec;
    double   alert_cooldown_sec;

    char     alert_endpoint[MON_URL_MAX];
    char     alert_api_key[MON_KEY_MAX];

    /* --- state --- */
    Window   error_win;     /* every event; hi_count = ERROR+ */
    Window   crit_win;      /* CRITICAL events only           */

    double   last_alert_error_rate;
    double   last_alert_crit_burst;

    uint64_t events_observed;
    uint64_t alerts_fired;
    uint64_t alerts_failed;     /* alert POST not 2xx / network error */

    pthread_mutex_t mu;
    bool_t          initialised;
} Monitor;

LogSysErr monitor_init(Monitor *m);
LogSysErr monitor_destroy(Monitor *m);

/**
 * Observe a single event: update windows, evaluate rules, and dispatch
 * any triggered alert (network I/O performed outside the lock).
 */
LogSysErr monitor_observe(Monitor *m, const LogEvent *e);

LogSysErr monitor_stats(Monitor *m,
                        uint64_t *events_observed,
                        uint64_t *alerts_fired,
                        uint64_t *alerts_failed);

#endif /* MONITOR_H */
