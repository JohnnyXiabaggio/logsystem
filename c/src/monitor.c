/**
 * @file monitor.c
 * @brief Issue monitor implementation.
 *
 * - All loops have an explicit upper bound (MISRA 22.10 / safety).
 * - Division-by-zero is impossible (count > 0 guard).
 * - Alert dispatch uses a small dedicated HTTP function; the global
 *   Uploader is not reused (cleaner separation, no recursive locking).
 * - All return values checked.
 */

#include "monitor.h"

#include <string.h>
#include <stdio.h>
#include <time.h>
#include <math.h>

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
/* ------------------------------------------------------------------ */

static double mono_now(void)
{
    struct timespec ts;
    (void)clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + ((double)ts.tv_nsec * 1e-9);
}

/* Push WinEntry into circular buffer (bounded; oldest is evicted on full). */
static void win_push_entry(WinEntry *buf,
                            uint32_t *head, uint32_t *tail, uint32_t *count,
                            double ts, Severity sev)
{
    if (*count >= MON_WIN_MAX) {
        *head = (*head + 1U) % MON_WIN_MAX;
        (*count)--;
    }
    buf[*tail].ts  = ts;
    buf[*tail].sev = sev;
    *tail = (*tail + 1U) % MON_WIN_MAX;
    (*count)++;
}

/* Evict WinEntry entries older than cutoff.  Bounded by MON_WIN_MAX
 * iterations regardless of state (functional safety). */
static void win_evict_entry(WinEntry *buf,
                             uint32_t *head, uint32_t *count, double cutoff)
{
    uint32_t guard = MON_WIN_MAX;
    while ((guard > 0U) && (*count > 0U) && (buf[*head].ts < cutoff)) {
        *head = (*head + 1U) % MON_WIN_MAX;
        (*count)--;
        guard--;
    }
}

static void win_push_ts(double *buf,
                         uint32_t *head, uint32_t *tail, uint32_t *count,
                         double ts)
{
    if (*count >= MON_WIN_MAX) {
        *head = (*head + 1U) % MON_WIN_MAX;
        (*count)--;
    }
    buf[*tail] = ts;
    *tail = (*tail + 1U) % MON_WIN_MAX;
    (*count)++;
}

static void win_evict_ts(double *buf,
                          uint32_t *head, uint32_t *count, double cutoff)
{
    uint32_t guard = MON_WIN_MAX;
    while ((guard > 0U) && (*count > 0U) && (buf[*head] < cutoff)) {
        *head = (*head + 1U) % MON_WIN_MAX;
        (*count)--;
        guard--;
    }
}

/* ------------------------------------------------------------------ */
/* Alert dispatch — a minimal, self-contained POST.                   */
/* The bearer token is wiped from local buffers after the call.       */
/* ------------------------------------------------------------------ */

#include <unistd.h>
#include <sys/socket.h>
#include <netdb.h>
#include <sys/time.h>
#include <stdlib.h>

static LogSysErr post_alert_http(const char *url, const char *key,
                                  const char *body, uint32_t body_len);

static void post_alert(Monitor *m, const char *title, const char *desc,
                        Severity sev)
{
    if ((m != NULL) && (title != NULL) && (desc != NULL)) {
        char            id[EVT_ID_LEN];
        struct timespec now;
        char            ts[32];
        char            title_j[256];
        char            desc_j[512];
        char            body[2048];
        int             n;

        (void)uuid_gen(id, sizeof(id));
        (void)clock_gettime(CLOCK_REALTIME, &now);
        (void)ts_iso8601(&now, ts, sizeof(ts));
        (void)json_escape(title_j, sizeof(title_j), title);
        (void)json_escape(desc_j,  sizeof(desc_j),  desc);

        n = snprintf(body, sizeof(body),
            "{\"alert_id\":\"%s\",\"triggered_at\":\"%s\","
            "\"severity\":\"%s\",\"title\":%s,\"description\":%s}",
            id, ts, sev_label(sev), title_j, desc_j);

        if ((n > 0) && ((size_t)n < sizeof(body))) {
            (void)fprintf(stderr, "[monitor] ALERT [%s] %s — %s\n",
                          sev_label(sev), title, desc);

            if (m->alert_endpoint[0] != '\0') {
                (void)post_alert_http(m->alert_endpoint,
                                      m->alert_api_key,
                                      body, (uint32_t)n);
            }
        }
        /* Wipe local buffers — defence in depth (CWE-316). */
        (void)memset(body, 0, sizeof(body));
    }
}

/* ------------------------------------------------------------------ */
/* Rule evaluation — runs with the monitor mutex held on entry; may  */
/* release/re-acquire it across alert dispatch to avoid I/O under    */
/* the lock.                                                         */
/* ------------------------------------------------------------------ */

static void check_rules(Monitor *m, double now)
{
    /* Rule 1: high error rate. */
    if (m->error_win_count >= 10U) {
        uint32_t errors = 0U;
        uint32_t idx    = m->error_win_head;
        uint32_t i;
        for (i = 0U; i < m->error_win_count; i++) {
            if (m->error_win[idx].sev >= SEV_ERROR) {
                errors++;
            }
            idx = (idx + 1U) % MON_WIN_MAX;
        }
        {
            const double rate = (double)errors / (double)m->error_win_count;
            const bool_t cool =
                ((now - m->last_alert_error_rate) >= m->alert_cooldown_sec)
                    ? LOGSYS_TRUE : LOGSYS_FALSE;
            if ((rate >= m->error_rate_threshold) && (cool == LOGSYS_TRUE)) {
                char desc[256];
                m->last_alert_error_rate = now;
                m->alerts_fired++;
                (void)snprintf(desc, sizeof(desc),
                    "Error rate %.1f%% (threshold %.1f%%) — "
                    "%u/%u events in %.0fs",
                    rate * 100.0,
                    m->error_rate_threshold * 100.0,
                    (unsigned)errors, (unsigned)m->error_win_count,
                    m->error_rate_window_sec);
                (void)pthread_mutex_unlock(&m->mu);
                post_alert(m, "High Error Rate Detected", desc, SEV_ERROR);
                (void)pthread_mutex_lock(&m->mu);
            }
        }
    }

    /* Rule 2: critical burst. */
    if (m->crit_win_count >= m->critical_burst_threshold) {
        const bool_t cool =
            ((now - m->last_alert_crit_burst) >= m->alert_cooldown_sec)
                ? LOGSYS_TRUE : LOGSYS_FALSE;
        if (cool == LOGSYS_TRUE) {
            char desc[256];
            m->last_alert_crit_burst = now;
            m->alerts_fired++;
            (void)snprintf(desc, sizeof(desc),
                "%u CRITICAL events in %.0fs (threshold %u)",
                (unsigned)m->crit_win_count,
                m->critical_burst_window_sec,
                (unsigned)m->critical_burst_threshold);
            (void)pthread_mutex_unlock(&m->mu);
            post_alert(m, "Critical Event Burst", desc, SEV_CRITICAL);
            (void)pthread_mutex_lock(&m->mu);
        }
    }
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
        /* Wipe API key on shutdown. */
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
        const double now = mono_now();
        m->events_observed++;

        win_push_entry(m->error_win,
                       &m->error_win_head, &m->error_win_tail,
                       &m->error_win_count, now, e->severity);
        win_evict_entry(m->error_win,
                        &m->error_win_head, &m->error_win_count,
                        now - m->error_rate_window_sec);

        if (e->severity >= SEV_CRITICAL) {
            win_push_ts(m->crit_win,
                        &m->crit_win_head, &m->crit_win_tail,
                        &m->crit_win_count, now);
            win_evict_ts(m->crit_win,
                         &m->crit_win_head, &m->crit_win_count,
                         now - m->critical_burst_window_sec);
        }

        check_rules(m, now);
        (void)pthread_mutex_unlock(&m->mu);
    }
    return rc;
}

LogSysErr monitor_stats(Monitor *m,
                        uint64_t *events_observed,
                        uint64_t *alerts_fired)
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
        (void)pthread_mutex_unlock(&m->mu);
    }
    return rc;
}

/* ------------------------------------------------------------------ */
/* Minimal HTTP POST for alert dispatch — http:// only.               */
/* (Compile-time choice: a full TLS uploader would use libcurl; the   */
/* monitor intentionally stays self-contained.)                        */
/* ------------------------------------------------------------------ */

static LogSysErr post_alert_http(const char *url, const char *key,
                                  const char *body, uint32_t body_len)
{
    LogSysErr rc = LOGSYS_OK;

    if ((url == NULL) || (body == NULL)) {
        rc = LOGSYS_ERR_PARAM;
    } else if (strncmp(url, "http://", 7U) != 0) {
        /* Alerts to https:// require libcurl build. */
        rc = LOGSYS_ERR_PARAM;
    } else {
        const char *p     = &url[7];
        const char *slash = strchr(p, '/');
        const char *colon = strchr(p, ':');
        char        host[128];
        char        path[128];
        int32_t     port  = 80;

        if (slash != NULL) {
            (void)snprintf(path, sizeof(path), "%s", slash);
            if ((colon != NULL) && (colon < slash)) {
                const ptrdiff_t hlen = colon - p;
                if ((hlen > 0) && ((size_t)hlen < sizeof(host))) {
                    (void)snprintf(host, sizeof(host), "%.*s",
                                   (int)hlen, p);
                    {
                        char *endp = NULL;
                        long  pv   = strtol(&colon[1], &endp, 10);
                        if ((endp != &colon[1]) &&
                            (pv >= (long)LOGSYS_PORT_MIN) &&
                            (pv <= (long)LOGSYS_PORT_MAX)) {
                            port = (int32_t)pv;
                        } else {
                            rc = LOGSYS_ERR_PARAM;
                        }
                    }
                } else {
                    rc = LOGSYS_ERR_PARAM;
                }
            } else {
                const ptrdiff_t hlen = slash - p;
                if ((hlen > 0) && ((size_t)hlen < sizeof(host))) {
                    (void)snprintf(host, sizeof(host), "%.*s",
                                   (int)hlen, p);
                } else {
                    rc = LOGSYS_ERR_PARAM;
                }
            }
        } else {
            (void)snprintf(path, sizeof(path), "%s", "/");
            (void)snprintf(host, sizeof(host), "%s", p);
        }

        if (rc == LOGSYS_OK) {
            struct addrinfo  hints;
            struct addrinfo *res = NULL;
            char             port_str[8];

            (void)memset(&hints, 0, sizeof(hints));
            hints.ai_family   = AF_UNSPEC;
            hints.ai_socktype = SOCK_STREAM;
            (void)snprintf(port_str, sizeof(port_str), "%d", (int)port);

            if (getaddrinfo(host, port_str, &hints, &res) != 0) {
                rc = LOGSYS_ERR_NET;
            } else {
                int sock = socket(res->ai_family, res->ai_socktype,
                                  res->ai_protocol);
                if (sock < 0) {
                    rc = LOGSYS_ERR_NET;
                } else {
                    struct timeval tv;
                    tv.tv_sec  = 5;
                    tv.tv_usec = 0;
                    (void)setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO,
                                     &tv, sizeof(tv));
                    (void)setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO,
                                     &tv, sizeof(tv));

                    if (connect(sock, res->ai_addr, res->ai_addrlen) != 0) {
                        rc = LOGSYS_ERR_NET;
                    } else {
                        char hdr[1024];
                        int  hlen = snprintf(hdr, sizeof(hdr),
                            "POST %s HTTP/1.1\r\n"
                            "Host: %s\r\n"
                            "Content-Type: application/json\r\n"
                            "Content-Length: %u\r\n"
                            "User-Agent: logsystem-c/1.0\r\n"
                            "%s%s%s"
                            "Connection: close\r\n\r\n",
                            path, host, (unsigned)body_len,
                            ((key != NULL) && (key[0] != '\0'))
                                ? "Authorization: Bearer " : "",
                            ((key != NULL) && (key[0] != '\0'))
                                ? key : "",
                            ((key != NULL) && (key[0] != '\0'))
                                ? "\r\n" : "");
                        if ((hlen < 0) || ((size_t)hlen >= sizeof(hdr))) {
                            rc = LOGSYS_ERR_TRUNC;
                        } else {
                            ssize_t sh = send(sock, hdr, (size_t)hlen, 0);
                            ssize_t sb = (sh > 0) ?
                                send(sock, body, body_len, 0) : (ssize_t)-1;
                            if ((sh < 0) || (sb < 0)) {
                                rc = LOGSYS_ERR_NET;
                            }
                        }
                        (void)memset(hdr, 0, sizeof(hdr)); /* CWE-316 */
                    }
                    (void)close(sock);
                }
                freeaddrinfo(res);
            }
        }
    }
    return rc;
}
