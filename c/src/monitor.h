/**
 * @file monitor.h
 * @brief Cloud issue monitor: rolling-window anomaly detection + alerting.
 *
 * Compliance:
 *   - Rolling windows are statically sized.
 *   - All loops bounded by MON_WIN_MAX.
 *   - Division-by-zero guarded.
 */

#ifndef MONITOR_H
#define MONITOR_H

#include "logsys_types.h"
#include "log_event.h"
#include "uploader.h"
#include <pthread.h>

typedef struct {
    double   ts;      /* seconds, CLOCK_MONOTONIC */
    Severity sev;
} WinEntry;

typedef struct {
    /* --- configuration --- */
    double   error_rate_threshold;       /* fraction in [0.0, 1.0] */
    double   error_rate_window_sec;
    uint32_t critical_burst_threshold;
    double   critical_burst_window_sec;
    double   alert_cooldown_sec;

    char     alert_endpoint[UPLOADER_URL_MAX];
    char     alert_api_key[UPLOADER_KEY_MAX];

    /* --- state (windows are circular buffers) --- */
    WinEntry error_win[MON_WIN_MAX];
    uint32_t error_win_head;
    uint32_t error_win_tail;
    uint32_t error_win_count;

    double   crit_win[MON_WIN_MAX];
    uint32_t crit_win_head;
    uint32_t crit_win_tail;
    uint32_t crit_win_count;

    double   last_alert_error_rate;
    double   last_alert_crit_burst;

    uint64_t events_observed;
    uint64_t alerts_fired;

    pthread_mutex_t mu;
    bool_t          initialised;
} Monitor;

LogSysErr monitor_init(Monitor *m);
LogSysErr monitor_destroy(Monitor *m);

/**
 * Observe a single event.  Internally locks the monitor, updates the
 * rolling windows, evaluates the alert rules, and dispatches any
 * triggered alerts.
 */
LogSysErr monitor_observe(Monitor *m, const LogEvent *e);

LogSysErr monitor_stats(Monitor *m,
                        uint64_t *events_observed,
                        uint64_t *alerts_fired);

#endif /* MONITOR_H */
