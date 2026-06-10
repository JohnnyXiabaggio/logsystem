/**
 * @file monitor.c
 * @brief Issue monitor implementation.
 *
 * - O(1) rule evaluation per event (running counters on push/evict).
 * - No network I/O under the monitor lock: alerts are snapshotted into
 *   locals while locked and POSTed after unlock.
 * - HTTP transport shared with the uploader (http_client.c).
 * - All loops bounded; all return values checked.
 */

#include "monitor.h"
#include "http_client.h"

#include <string.h>
#include <stdio.h>
#include <time.h>

/* ------------------------------------------------------------------ */
/* Pending-alert snapshot built under the lock, dispatched after.      */
/* ------------------------------------------------------------------ */

#define MON_MAX_PENDING (2U)    /* one per rule per observe call */

typedef struct {
    char     title[64];
    char     desc[256];
    Severity sev;
} PendingAlert;

/* ------------------------------------------------------------------ */
/* Time                                                                */
/* ------------------------------------------------------------------ */

static double mono_now(void)
{
    struct timespec ts;
    (void)clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + ((double)ts.tv_nsec * 1e-9);
}

/* ------------------------------------------------------------------ */
/* Window — one implementation, O(1) counters                          */
/* ------------------------------------------------------------------ */

static void win_push(Window *w, double ts, Severity sev)
{
    if (w->count >= MON_WIN_MAX) {
        /* Overwrite oldest: retire its counter contribution first. */
        if (w->e[w->head].sev >= w->bar) {
            w->hi_count--;
        }
        w->head = (w->head + 1U) % MON_WIN_MAX;
        w->count--;
    }
    {
        const uint32_t tail = (w->head + w->count) % MON_WIN_MAX;
        w->e[tail].ts  = ts;
        w->e[tail].sev = sev;
        w->count++;
        if (sev >= w->bar) {
            w->hi_count++;
        }
    }
}

static void win_evict(Window *w, double cutoff)
{
    uint32_t guard = MON_WIN_MAX;
    while ((guard > 0U) && (w->count > 0U) &&
           (w->e[w->head].ts < cutoff)) {
        if (w->e[w->head].sev >= w->bar) {
            w->hi_count--;
        }
        w->head = (w->head + 1U) % MON_WIN_MAX;
        w->count--;
        guard--;
    }
}

/* ------------------------------------------------------------------ */
/* Rule evaluation — called WITH the lock held; produces snapshots,    */
/* performs no I/O.                                                    */
/* ------------------------------------------------------------------ */

static uint8_t check_rules(Monitor *m, double now,
                            PendingAlert pending[MON_MAX_PENDING])
{
    uint8_t npending = 0U;

    /* Rule 1: high error rate (O(1) — counters, no scan). */
    if (m->error_win.count >= 10U) {
        const double rate =
            (double)m->error_win.hi_count / (double)m->error_win.count;
        if ((rate >= m->error_rate_threshold) &&
            ((now - m->last_alert_error_rate) >= m->alert_cooldown_sec)) {
            m->last_alert_error_rate = now;
            m->alerts_fired++;
            (void)snprintf(pending[npending].title,
                           sizeof(pending[npending].title),
                           "%s", "High Error Rate Detected");
            (void)snprintf(pending[npending].desc,
                           sizeof(pending[npending].desc),
                "Error rate %.1f%% (threshold %.1f%%) — %u/%u events in %.0fs",
                rate * 100.0,
                m->error_rate_threshold * 100.0,
                (unsigned)m->error_win.hi_count,
                (unsigned)m->error_win.count,
                m->error_rate_window_sec);
            pending[npending].sev = SEV_ERROR;
            npending++;
        }
    }

    /* Rule 2: critical burst (count IS the burst size). */
    if ((m->crit_win.count >= m->critical_burst_threshold) &&
        ((now - m->last_alert_crit_burst) >= m->alert_cooldown_sec)) {
        m->last_alert_crit_burst = now;
        m->alerts_fired++;
        (void)snprintf(pending[npending].title,
                       sizeof(pending[npending].title),
                       "%s", "Critical Event Burst");
        (void)snprintf(pending[npending].desc,
                       sizeof(pending[npending].desc),
            "%u CRITICAL events in %.0fs (threshold %u)",
            (unsigned)m->crit_win.count,
            m->critical_burst_window_sec,
            (unsigned)m->critical_burst_threshold);
        pending[npending].sev = SEV_CRITICAL;
        npending++;
    }

    return npending;
}

/* ------------------------------------------------------------------ */
/* Alert dispatch — runs WITHOUT the lock                              */
/* ------------------------------------------------------------------ */

static bool_t dispatch_alert(const char *endpoint, const char *key,
                              const PendingAlert *a)
{
    bool_t delivered = LOGSYS_TRUE;
    char   id[EVT_ID_LEN];
    struct timespec now;
    char   ts[32];
    char   title_j[80];
    char   desc_j[320];
    char   body[600];
    int    n;

    (void)uuid_gen(id, sizeof(id));
    (void)clock_gettime(CLOCK_REALTIME, &now);
    (void)ts_iso8601(&now, ts, sizeof(ts));
    (void)json_escape(title_j, sizeof(title_j), a->title);
    (void)json_escape(desc_j,  sizeof(desc_j),  a->desc);

    n = snprintf(body, sizeof(body),
        "{\"alert_id\":\"%s\",\"triggered_at\":\"%s\","
        "\"severity\":\"%s\",\"title\":%s,\"description\":%s}",
        id, ts, sev_label(a->sev), title_j, desc_j);

    (void)fprintf(stderr, "[monitor] ALERT [%s] %s — %s\n",
                  sev_label(a->sev), a->title, a->desc);

    if ((n <= 0) || ((size_t)n >= sizeof(body))) {
        delivered = LOGSYS_FALSE;
    } else if (endpoint[0] == '\0') {
        /* No endpoint configured — stderr only, counts as delivered. */
    } else {
        long status = 0L;
        if ((http_post(endpoint, key, body, (uint32_t)n,
                       5U, &status) != LOGSYS_OK) ||
            (status < 200L) || (status >= 300L)) {
            (void)fprintf(stderr,
                "[monitor] alert POST failed (status=%ld)\n", status);
            delivered = LOGSYS_FALSE;
        }
    }
    return delivered;
}

/* ------------------------------------------------------------------ */
/* Public API                                                          */
/* ------------------------------------------------------------------ */

LogSysErr monitor_init(Monitor *m)
{
    LogSysErr rc = LOGSYS_OK;

    if (m == NULL) {
        rc = LOGSYS_ERR_PARAM;
    } else {
        (void)memset(m, 0, sizeof(*m));
        m->error_rate_threshold      = 0.10;
        m->error_rate_window_sec     = 60.0;
        m->critical_burst_threshold  = 5U;
        m->critical_burst_window_sec = 30.0;
        m->alert_cooldown_sec        = 300.0;
        m->last_alert_error_rate     = -1.0e18;
        m->last_alert_crit_burst     = -1.0e18;
        m->error_win.bar             = SEV_ERROR;
        m->crit_win.bar              = SEV_CRITICAL;

        if (pthread_mutex_init(&m->mu, NULL) != 0) {
            rc = LOGSYS_ERR_SYS;
        } else {
            m->initialised = LOGSYS_TRUE;
        }
    }
    return rc;
}

LogSysErr monitor_destroy(Monitor *m)
{
    LogSysErr rc = LOGSYS_OK;

    if (m == NULL) {
        rc = LOGSYS_ERR_PARAM;
    } else if (m->initialised == LOGSYS_FALSE) {
        rc = LOGSYS_ERR_STATE;
    } else {
        (void)pthread_mutex_destroy(&m->mu);
        m->initialised = LOGSYS_FALSE;
        /* Wipe API key on shutdown (CWE-316). */
        (void)memset(m->alert_api_key, 0, sizeof(m->alert_api_key));
    }
    return rc;
}

LogSysErr monitor_observe(Monitor *m, const LogEvent *e)
{
    LogSysErr rc = LOGSYS_OK;

    if ((m == NULL) || (e == NULL)) {
        rc = LOGSYS_ERR_PARAM;
    } else if (m->initialised == LOGSYS_FALSE) {
        rc = LOGSYS_ERR_STATE;
    } else if (pthread_mutex_lock(&m->mu) != 0) {
        rc = LOGSYS_ERR_SYS;
    } else {
        PendingAlert pending[MON_MAX_PENDING];
        uint8_t      npending;
        char         endpoint[MON_URL_MAX];
        char         key[MON_KEY_MAX];
        const double now = mono_now();

        m->events_observed++;

        win_push(&m->error_win, now, e->severity);
        win_evict(&m->error_win, now - m->error_rate_window_sec);

        if (e->severity >= SEV_CRITICAL) {
            win_push(&m->crit_win, now, e->severity);
        }
        win_evict(&m->crit_win, now - m->critical_burst_window_sec);

        npending = check_rules(m, now, pending);

        /* Snapshot dispatch config under the lock. */
        if (npending > 0U) {
            (void)snprintf(endpoint, sizeof(endpoint), "%s",
                           m->alert_endpoint);
            (void)snprintf(key, sizeof(key), "%s", m->alert_api_key);
        }
        (void)pthread_mutex_unlock(&m->mu);

        /* Network I/O outside the lock. */
        if (npending > 0U) {
            uint8_t  i;
            uint64_t failed = 0U;
            for (i = 0U; i < npending; i++) {
                if (dispatch_alert(endpoint, key,
                                   &pending[i]) == LOGSYS_FALSE) {
                    failed++;
                }
            }
            (void)memset(key, 0, sizeof(key));   /* CWE-316 */
            if (failed > 0U) {
                if (pthread_mutex_lock(&m->mu) == 0) {
                    m->alerts_failed += failed;
                    (void)pthread_mutex_unlock(&m->mu);
                }
            }
        }
    }
    return rc;
}

LogSysErr monitor_stats(Monitor *m,
                        uint64_t *events_observed,
                        uint64_t *alerts_fired,
                        uint64_t *alerts_failed)
{
    LogSysErr rc = LOGSYS_OK;

    if (m == NULL) {
        rc = LOGSYS_ERR_PARAM;
    } else if (m->initialised == LOGSYS_FALSE) {
        rc = LOGSYS_ERR_STATE;
    } else if (pthread_mutex_lock(&m->mu) != 0) {
        rc = LOGSYS_ERR_SYS;
    } else {
        if (events_observed != NULL) { *events_observed = m->events_observed; }
        if (alerts_fired    != NULL) { *alerts_fired    = m->alerts_fired;    }
        if (alerts_failed   != NULL) { *alerts_failed   = m->alerts_failed;   }
        (void)pthread_mutex_unlock(&m->mu);
    }
    return rc;
}
