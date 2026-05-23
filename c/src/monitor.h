#ifndef MONITOR_H
#define MONITOR_H

#include "log_event.h"
#include "uploader.h"   /* for alert POST */
#include <pthread.h>
#include <stdint.h>

/* Rolling window entry */
typedef struct {
    double   ts;   /* time_t seconds (monotonic) */
    Severity sev;
} WinEntry;

#define MON_WIN_MAX 4096   /* max events held across both windows */

typedef struct {
    /* --- config --- */
    double error_rate_threshold;       /* fraction of ERROR+ to trigger, e.g. 0.10 */
    double error_rate_window_sec;      /* rolling window length */
    int    critical_burst_threshold;   /* count of CRITICAL to trigger */
    double critical_burst_window_sec;
    double alert_cooldown_sec;

    char   alert_endpoint[UPLOADER_URL_MAX];
    char   alert_api_key[UPLOADER_KEY_MAX];

    /* --- state --- */
    WinEntry error_win[MON_WIN_MAX];
    int      error_win_head, error_win_tail, error_win_count;

    double   crit_win[MON_WIN_MAX];
    int      crit_win_head, crit_win_tail, crit_win_count;

    double   last_alert_error_rate;
    double   last_alert_crit_burst;

    uint64_t events_observed;
    uint64_t alerts_fired;

    pthread_mutex_t mu;
} Monitor;

void monitor_init(Monitor *m);
void monitor_observe(Monitor *m, const LogEvent *e);
void monitor_stats(const Monitor *m,
                   uint64_t *events_observed, uint64_t *alerts_fired);

#endif /* MONITOR_H */
