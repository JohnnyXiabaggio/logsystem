/**
 * @file uploader.c
 * @brief Batch upload with bounded exponential-backoff retry.
 *
 * Transport lives in http_client.c (shared with the monitor).
 *
 * Performance (ECU):
 *   - Events are serialised DIRECTLY into the static batch buffer —
 *     no per-event stack staging copy.
 *   - The batch buffer is log data, not secret material; it is not
 *     wiped between batches (the bearer token never enters it — the
 *     Authorization header is built and wiped inside http_client).
 *
 * Functional safety:
 *   - No dynamic memory (MISRA 21.3); batch buffer is file-scope static.
 *   - Retry loop bounded by retry_attempts; backoff doubling is
 *     overflow-guarded.
 */

#include "uploader.h"
#include "http_client.h"

#include <string.h>
#include <stdio.h>
#include <time.h>
#include <pthread.h>

/* ------------------------------------------------------------------ */
/* Static batch buffer                                                 */
/* ------------------------------------------------------------------ */

/* Per-event worst-case JSON budget. */
#define PER_EVT_BUDGET   ((EVT_MSG_MAX * 2U) + (EVT_SRC_MAX * 2U) + 256U)

/* Total batch JSON budget. */
#define BATCH_JSON_MAX   ((UPLOADER_BATCH_MAX * PER_EVT_BUDGET) + 256U)

/* Cap at 16 MiB to keep .bss bounded on small targets. */
LOGSYS_STATIC_ASSERT(BATCH_JSON_MAX <= (16U * 1024U * 1024U), batch_size_sane);

static char            s_batch_buf[BATCH_JSON_MAX];
static pthread_mutex_t s_batch_mu = PTHREAD_MUTEX_INITIALIZER;

/* ------------------------------------------------------------------ */
/* Batch serialisation — events written in place, no staging copy     */
/* ------------------------------------------------------------------ */

static LogSysErr build_batch_json(const LogEvent *events,
                                   uint32_t        count,
                                   const char     *batch_id,
                                   uint32_t       *out_len)
{
    LogSysErr rc = LOGSYS_OK;
    struct timespec now;
    char            ts[32];
    int             n;
    uint32_t        off;

    (void)clock_gettime(CLOCK_REALTIME, &now);
    if (ts_iso8601(&now, ts, sizeof(ts)) != LOGSYS_OK) {
        rc = LOGSYS_ERR_TRUNC;
    } else {
        n = snprintf(s_batch_buf, BATCH_JSON_MAX,
            "{\"batch_id\":\"%s\",\"created_at\":\"%s\","
            "\"event_count\":%u,\"events\":[",
            batch_id, ts, (unsigned int)count);

        if ((n < 0) || ((uint32_t)n >= BATCH_JSON_MAX)) {
            rc = LOGSYS_ERR_TRUNC;
        } else {
            uint32_t i;
            off = (uint32_t)n;
            for (i = 0U; (i < count) && (rc == LOGSYS_OK); i++) {
                uint32_t evt_len = 0U;

                if (i > 0U) {
                    if ((off + 1U) >= BATCH_JSON_MAX) {
                        rc = LOGSYS_ERR_TRUNC;
                    } else {
                        s_batch_buf[off] = ',';
                        off++;
                    }
                }
                if (rc == LOGSYS_OK) {
                    rc = evt_to_json(&events[i], &s_batch_buf[off],
                                     BATCH_JSON_MAX - off, &evt_len);
                    if (rc == LOGSYS_OK) {
                        off += evt_len;
                    }
                }
            }
            if (rc == LOGSYS_OK) {
                if ((off + 3U) > BATCH_JSON_MAX) {
                    rc = LOGSYS_ERR_TRUNC;
                } else {
                    s_batch_buf[off] = ']';
                    off++;
                    s_batch_buf[off] = '}';
                    off++;
                    s_batch_buf[off] = '\0';
                    *out_len = off;
                }
            }
        }
    }
    return rc;
}

/* ------------------------------------------------------------------ */
/* Retry classification                                                */
/* ------------------------------------------------------------------ */

static bool_t is_retryable_status(long status)
{
    bool_t r = LOGSYS_FALSE;
    if ((status == 429L) ||
        (status == 500L) || (status == 502L) ||
        (status == 503L) || (status == 504L)) {
        r = LOGSYS_TRUE;
    }
    return r;
}

static void sleep_ms(uint32_t ms)
{
    struct timespec ts;
    ts.tv_sec  = (time_t)(ms / 1000U);
    ts.tv_nsec = (long)((ms % 1000U) * 1000000U);
    (void)nanosleep(&ts, NULL);
}

/* ------------------------------------------------------------------ */
/* Public API                                                          */
/* ------------------------------------------------------------------ */

LogSysErr uploader_init(Uploader *u)
{
    LogSysErr rc = LOGSYS_OK;

    if (u == NULL) {
        rc = LOGSYS_ERR_PARAM;
    } else {
        (void)memset(u, 0, sizeof(*u));
        u->retry_attempts = 4U;
        u->backoff_ms     = 2000U;
        u->timeout_sec    = (uint32_t)HTTP_TIMEOUT_SEC;
        u->dry_run        = LOGSYS_FALSE;
        u->initialised    = LOGSYS_TRUE;
    }
    return rc;
}

LogSysErr uploader_send(Uploader *u, const LogEvent *events, uint32_t count)
{
    LogSysErr overall = LOGSYS_OK;

    if ((u == NULL) || (events == NULL)) {
        overall = LOGSYS_ERR_PARAM;
    } else if (u->initialised == LOGSYS_FALSE) {
        overall = LOGSYS_ERR_STATE;
    } else if (count == 0U) {
        /* nothing to do — explicit success */
    } else if (pthread_mutex_lock(&s_batch_mu) != 0) {
        overall = LOGSYS_ERR_SYS;
    } else {
        uint32_t off;
        for (off = 0U; off < count; off += UPLOADER_BATCH_MAX) {
            const uint32_t remain = count - off;
            const uint32_t chunk  =
                (remain > UPLOADER_BATCH_MAX) ? UPLOADER_BATCH_MAX : remain;

            char     batch_id[EVT_ID_LEN];
            uint32_t body_len = 0U;
            (void)uuid_gen(batch_id, sizeof(batch_id));

            if (build_batch_json(&events[off], chunk, batch_id,
                                  &body_len) != LOGSYS_OK) {
                u->total_failed += chunk;
                overall          = LOGSYS_ERR_TRUNC;
            } else {
                u->total_batches++;

                if ((u->dry_run == LOGSYS_TRUE) ||
                    (u->endpoint[0] == '\0')) {
                    /* MISRA 21.6 deviation: stderr diagnostics. */
                    (void)fprintf(stderr,
                        "[uploader] DRY-RUN batch=%.*s events=%u bytes=%u\n",
                        8, batch_id, (unsigned)chunk, (unsigned)body_len);
                    u->total_sent += chunk;
                } else {
                    uint32_t delay   = u->backoff_ms;
                    bool_t   sent_ok = LOGSYS_FALSE;
                    uint8_t  attempt;

                    /* Bounded retry loop — max retry_attempts (≤255). */
                    for (attempt = 1U;
                         (attempt <= u->retry_attempts) &&
                         (sent_ok == LOGSYS_FALSE);
                         attempt++) {
                        long      status = 0L;
                        LogSysErr rc;

                        rc = http_post(u->endpoint, u->api_key,
                                       s_batch_buf, body_len,
                                       u->timeout_sec, &status);
                        if ((rc == LOGSYS_OK) &&
                            (status >= 200L) && (status < 300L)) {
                            u->total_sent += chunk;
                            sent_ok        = LOGSYS_TRUE;
                        } else {
                            bool_t do_retry =
                                ((rc != LOGSYS_OK) ||
                                 (is_retryable_status(status) == LOGSYS_TRUE))
                                ? LOGSYS_TRUE : LOGSYS_FALSE;

                            /* Diagnostic — no secrets in this message. */
                            (void)fprintf(stderr,
                                "[uploader] batch=%.*s attempt=%u "
                                "status=%ld %s\n",
                                8, batch_id, (unsigned)attempt, status,
                                (do_retry == LOGSYS_TRUE)
                                    ? "(retry)" : "(fatal)");

                            if ((do_retry == LOGSYS_FALSE) ||
                                (attempt == u->retry_attempts)) {
                                break;
                            }
                            sleep_ms(delay);
                            if (delay <= (UINT32_MAX / 2U)) {
                                delay *= 2U;
                            }
                        }
                    }
                    if (sent_ok == LOGSYS_FALSE) {
                        u->total_failed += chunk;
                        overall          = LOGSYS_ERR_NET;
                    }
                }
            }
        }
        (void)pthread_mutex_unlock(&s_batch_mu);
    }
    return overall;
}
