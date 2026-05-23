#include "monitor.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <math.h>

/* ------------------------------------------------------------------ */
/* Internal helpers                                                    */
/* ------------------------------------------------------------------ */

static double mono_now(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec * 1e-9;
}

/* Circular buffer push for WinEntry */
static void win_push_entry(WinEntry *buf, int *head, int *tail, int *count,
                            double ts, Severity sev) {
    if (*count >= MON_WIN_MAX) {
        /* Overwrite oldest */
        *head = (*head + 1) % MON_WIN_MAX;
        (*count)--;
    }
    buf[*tail] = (WinEntry){ .ts = ts, .sev = sev };
    *tail = (*tail + 1) % MON_WIN_MAX;
    (*count)++;
}

/* Evict entries older than cutoff from head */
static void win_evict_entry(WinEntry *buf, int *head, int *count, double cutoff) {
    while (*count > 0 && buf[*head].ts < cutoff) {
        *head = (*head + 1) % MON_WIN_MAX;
        (*count)--;
    }
}

/* Circular buffer push for timestamps only */
static void win_push_ts(double *buf, int *head, int *tail, int *count, double ts) {
    if (*count >= MON_WIN_MAX) {
        *head = (*head + 1) % MON_WIN_MAX;
        (*count)--;
    }
    buf[*tail] = ts;
    *tail = (*tail + 1) % MON_WIN_MAX;
    (*count)++;
}

static void win_evict_ts(double *buf, int *head, int *count, double cutoff) {
    while (*count > 0 && buf[*head] < cutoff) {
        *head = (*head + 1) % MON_WIN_MAX;
        (*count)--;
    }
}

/* ------------------------------------------------------------------ */
/* Alert dispatch                                                      */
/* ------------------------------------------------------------------ */

static void post_alert(Monitor *m, const char *title, const char *desc,
                        Severity sev) {
    /* Build minimal alert JSON */
    char id[EVT_ID_LEN];
    uuid_gen(id);
    struct timespec now;
    clock_gettime(CLOCK_REALTIME, &now);
    char ts[32];
    ts_iso8601(&now, ts, sizeof(ts));

    char body[2048];
    char title_j[256], desc_j[512];
    json_escape(title_j, sizeof(title_j), title);
    json_escape(desc_j,  sizeof(desc_j),  desc);
    snprintf(body, sizeof(body),
        "{\"alert_id\":\"%s\",\"triggered_at\":\"%s\","
        "\"severity\":\"%s\",\"title\":%s,\"description\":%s}",
        id, ts, sev_label(sev), title_j, desc_j);

    fprintf(stderr, "[monitor] ALERT [%s] %s — %s\n",
            sev_label(sev), title, desc);

    if (m->alert_endpoint[0] == '\0') return;

    /* Reuse uploader HTTP logic via a temporary Uploader */
    Uploader u;
    uploader_init(&u);
    snprintf(u.endpoint, sizeof(u.endpoint), "%s", m->alert_endpoint);
    snprintf(u.api_key,  sizeof(u.api_key),  "%s", m->alert_api_key);
    u.timeout_sec    = 5.0;
    u.retry_attempts = 2;
    u.dry_run        = 0;

    /* Wrap alert in a single synthetic LogEvent so uploader_send works */
    LogEvent ae;
    evt_init(&ae, body, sev, "monitor");
    /* Send raw JSON body directly via a mini POST */
    /* We'll just call do_http_post indirectly: create a 1-event fake batch */
    uploader_send(&u, &ae, 1);
}

/* ------------------------------------------------------------------ */
/* Rule evaluation (called with lock held)                             */
/* ------------------------------------------------------------------ */

static void check_rules(Monitor *m, double now) {
    /* Rule 1: high error rate */
    int total = m->error_win_count;
    if (total >= 10) {
        int errors = 0;
        int idx = m->error_win_head;
        for (int i = 0; i < total; i++) {
            if (m->error_win[idx].sev >= SEV_ERROR) errors++;
            idx = (idx + 1) % MON_WIN_MAX;
        }
        double rate = (double)errors / (double)total;
        if (rate >= m->error_rate_threshold &&
            now - m->last_alert_error_rate >= m->alert_cooldown_sec) {
            m->last_alert_error_rate = now;
            m->alerts_fired++;
            char desc[256];
            snprintf(desc, sizeof(desc),
                "Error rate %.1f%% (threshold %.1f%%) — %d/%d events in %.0fs",
                rate * 100.0, m->error_rate_threshold * 100.0,
                errors, total, m->error_rate_window_sec);
            /* release lock before I/O */
            pthread_mutex_unlock(&m->mu);
            post_alert(m, "High Error Rate Detected", desc, SEV_ERROR);
            pthread_mutex_lock(&m->mu);
        }
    }

    /* Rule 2: critical burst */
    int burst = m->crit_win_count;
    if (burst >= m->critical_burst_threshold &&
        now - m->last_alert_crit_burst >= m->alert_cooldown_sec) {
        m->last_alert_crit_burst = now;
        m->alerts_fired++;
        char desc[256];
        snprintf(desc, sizeof(desc),
            "%d CRITICAL events in %.0fs (threshold %d)",
            burst, m->critical_burst_window_sec,
            m->critical_burst_threshold);
        pthread_mutex_unlock(&m->mu);
        post_alert(m, "Critical Event Burst", desc, SEV_CRITICAL);
        pthread_mutex_lock(&m->mu);
    }
}

/* ------------------------------------------------------------------ */
/* Public API                                                          */
/* ------------------------------------------------------------------ */

void monitor_init(Monitor *m) {
    memset(m, 0, sizeof(*m));
    m->error_rate_threshold      = 0.10;
    m->error_rate_window_sec     = 60.0;
    m->critical_burst_threshold  = 5;
    m->critical_burst_window_sec = 30.0;
    m->alert_cooldown_sec        = 300.0;
    m->last_alert_error_rate     = -1e18;  /* "never" */
    m->last_alert_crit_burst     = -1e18;
    pthread_mutex_init(&m->mu, NULL);
}

void monitor_observe(Monitor *m, const LogEvent *e) {
    double now = mono_now();
    pthread_mutex_lock(&m->mu);

    m->events_observed++;

    /* Append to error-rate window */
    win_push_entry(m->error_win,
                   &m->error_win_head, &m->error_win_tail, &m->error_win_count,
                   now, e->severity);
    win_evict_entry(m->error_win,
                    &m->error_win_head, &m->error_win_count,
                    now - m->error_rate_window_sec);

    /* Append to critical-burst window */
    if (e->severity >= SEV_CRITICAL) {
        win_push_ts(m->crit_win,
                    &m->crit_win_head, &m->crit_win_tail, &m->crit_win_count,
                    now);
        win_evict_ts(m->crit_win,
                     &m->crit_win_head, &m->crit_win_count,
                     now - m->critical_burst_window_sec);
    }

    check_rules(m, now);
    pthread_mutex_unlock(&m->mu);
}

void monitor_stats(const Monitor *m,
                   uint64_t *events_observed, uint64_t *alerts_fired) {
    pthread_mutex_lock((pthread_mutex_t *)&m->mu);
    if (events_observed) *events_observed = m->events_observed;
    if (alerts_fired)    *alerts_fired    = m->alerts_fired;
    pthread_mutex_unlock((pthread_mutex_t *)&m->mu);
}
