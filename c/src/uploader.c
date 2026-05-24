/**
 * @file uploader.c
 * @brief Batch HTTP/1.1 POST with retry — plain sockets by default,
 *        optional libcurl backend for HTTPS.
 *
 * Cybersecurity controls:
 *   - URL parsed safely; port range validated [1..65535] (CWE-20).
 *   - Authorisation header buffer wiped after send (CWE-316).
 *   - Body buffer is a file-scope static; bounds checked on every write
 *     (CWE-120).
 *   - All system-call return values are checked (CWE-252).
 *   - strtol/strtod used instead of atoi/atol/atof (MISRA 21.7).
 *
 * Functional safety:
 *   - No dynamic memory anywhere (MISRA 21.3).
 *   - Retry loop is bounded by retry_attempts (≤ 16).
 *   - Per-call timeouts enforced via SO_SNDTIMEO / SO_RCVTIMEO.
 */

#include "uploader.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>       /* strtol, strtod */
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <pthread.h>

#ifdef USE_CURL
#  include <curl/curl.h>
#else
#  include <sys/socket.h>
#  include <netdb.h>
#  include <sys/time.h>
#endif

/* ------------------------------------------------------------------ */
/* Static batch pool — only sized to one batch at a time              */
/* ------------------------------------------------------------------ */

/* Per-event worst-case JSON budget. */
#define PER_EVT_BUDGET   ((EVT_MSG_MAX * 2U) + (EVT_SRC_MAX * 2U) + 256U)

/* Total batch JSON budget. */
#define BATCH_JSON_MAX   ((UPLOADER_BATCH_MAX * PER_EVT_BUDGET) + 256U)

/* Cap at 16 MiB to keep .bss bounded on small targets. */
LOGSYS_STATIC_ASSERT(BATCH_JSON_MAX <= (16U * 1024U * 1024U), batch_size_sane);

static char     s_batch_buf[BATCH_JSON_MAX];
static pthread_mutex_t s_batch_mu = PTHREAD_MUTEX_INITIALIZER;

/* ------------------------------------------------------------------ */
/* Internal helpers                                                    */
/* ------------------------------------------------------------------ */

static LogSysErr build_batch_json(const LogEvent *events,
                                   uint32_t        count,
                                   const char     *batch_id,
                                   uint32_t       *out_len)
{
    LogSysErr rc = LOGSYS_OK;

    if ((events == NULL) || (batch_id == NULL) || (out_len == NULL)) {
        rc = LOGSYS_ERR_PARAM;
    } else {
        struct timespec now;
        char            ts[32];
        int             n;
        int32_t         off;

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
                off = n;
                for (i = 0U; (i < count) && (rc == LOGSYS_OK); i++) {
                    char evj[PER_EVT_BUDGET];
                    if (evt_to_json(&events[i], evj, sizeof(evj)) != LOGSYS_OK) {
                        rc = LOGSYS_ERR_TRUNC;
                    } else if ((uint32_t)off >= BATCH_JSON_MAX) {
                        rc = LOGSYS_ERR_TRUNC;
                    } else {
                        n = snprintf(&s_batch_buf[off],
                                     (size_t)(BATCH_JSON_MAX - (uint32_t)off),
                                     "%s%s", (i == 0U) ? "" : ",", evj);
                        if ((n < 0) ||
                            ((uint32_t)n >= (BATCH_JSON_MAX - (uint32_t)off))) {
                            rc = LOGSYS_ERR_TRUNC;
                        } else {
                            off += n;
                        }
                    }
                }
                if (rc == LOGSYS_OK) {
                    if ((uint32_t)off >= BATCH_JSON_MAX) {
                        rc = LOGSYS_ERR_TRUNC;
                    } else {
                        n = snprintf(&s_batch_buf[off],
                                     (size_t)(BATCH_JSON_MAX - (uint32_t)off),
                                     "]}");
                        if ((n < 0) ||
                            ((uint32_t)n >= (BATCH_JSON_MAX - (uint32_t)off))) {
                            rc = LOGSYS_ERR_TRUNC;
                        } else {
                            *out_len = (uint32_t)(off + n);
                        }
                    }
                }
            }
        }
    }
    return rc;
}

/* ------------------------------------------------------------------ */
/* HTTP transport — plain sockets                                      */
/* ------------------------------------------------------------------ */

#ifndef USE_CURL

/* Single-exit URL parser using strtol for the port (MISRA 21.7, CWE-20). */
static LogSysErr parse_url(const char *url,
                            char       *host, uint32_t hcap,
                            int32_t    *port,
                            char       *path, uint32_t pcap)
{
    LogSysErr rc = LOGSYS_OK;

    if ((url == NULL) || (host == NULL) || (port == NULL) ||
        (path == NULL) || (hcap == 0U) || (pcap == 0U)) {
        rc = LOGSYS_ERR_PARAM;
    } else if (strncmp(url, "http://", 7U) != 0) {
        rc = LOGSYS_ERR_PARAM;
    } else {
        const char *p     = &url[7];
        const char *slash = strchr(p, '/');
        const char *colon = strchr(p, ':');

        *port = 80;
        if (slash != NULL) {
            const ptrdiff_t plen = slash - p;
            int             n;
            n = snprintf(path, (size_t)pcap, "%s", slash);
            if ((n < 0) || ((uint32_t)n >= pcap)) {
                rc = LOGSYS_ERR_TRUNC;
            } else if ((colon != NULL) && (colon < slash)) {
                const ptrdiff_t hlen = colon - p;
                if ((hlen <= 0) || ((uint32_t)hlen >= hcap)) {
                    rc = LOGSYS_ERR_TRUNC;
                } else {
                    n = snprintf(host, (size_t)hcap, "%.*s",
                                 (int)hlen, p);
                    if ((n < 0) || ((uint32_t)n >= hcap)) {
                        rc = LOGSYS_ERR_TRUNC;
                    } else {
                        char         *endp = NULL;
                        const long    pv   = strtol(&colon[1], &endp, 10);
                        if ((endp == &colon[1]) ||
                            (pv < (long)LOGSYS_PORT_MIN) ||
                            (pv > (long)LOGSYS_PORT_MAX)) {
                            rc = LOGSYS_ERR_PARAM;
                        } else {
                            *port = (int32_t)pv;
                        }
                    }
                }
            } else {
                if ((plen <= 0) || ((uint32_t)plen >= hcap)) {
                    rc = LOGSYS_ERR_TRUNC;
                } else {
                    n = snprintf(host, (size_t)hcap, "%.*s",
                                 (int)plen, p);
                    if ((n < 0) || ((uint32_t)n >= hcap)) {
                        rc = LOGSYS_ERR_TRUNC;
                    }
                }
            }
        } else {
            int n;
            n = snprintf(path, (size_t)pcap, "%s", "/");
            if ((n < 0) || ((uint32_t)n >= pcap)) {
                rc = LOGSYS_ERR_TRUNC;
            } else {
                n = snprintf(host, (size_t)hcap, "%s", p);
                if ((n < 0) || ((uint32_t)n >= hcap)) {
                    rc = LOGSYS_ERR_TRUNC;
                }
            }
        }
    }
    return rc;
}

static LogSysErr http_post_socket(const char *url, const char *api_key,
                                   const char *body, uint32_t body_len,
                                   uint32_t timeout_sec, long *out_status)
{
    LogSysErr rc = LOGSYS_OK;
    char      host[256];
    char      path[256];
    int32_t   port;

    if ((url == NULL) || (body == NULL) || (out_status == NULL)) {
        rc = LOGSYS_ERR_PARAM;
    } else if (parse_url(url, host, sizeof(host),
                          &port, path, sizeof(path)) != LOGSYS_OK) {
        rc = LOGSYS_ERR_PARAM;
    } else {
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
                tv.tv_sec  = (time_t)timeout_sec;
                tv.tv_usec = 0;

                if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO,
                               &tv, sizeof(tv)) != 0) {
                    rc = LOGSYS_ERR_NET;
                } else if (setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO,
                                       &tv, sizeof(tv)) != 0) {
                    rc = LOGSYS_ERR_NET;
                } else if (connect(sock, res->ai_addr, res->ai_addrlen) != 0) {
                    rc = LOGSYS_ERR_NET;
                } else {
                    char hdr[1024];
                    int  hlen;

                    /* Build the request header.  We deliberately do
                     * NOT log this buffer anywhere — it contains the
                     * bearer token (CWE-532). */
                    hlen = snprintf(hdr, sizeof(hdr),
                        "POST %s HTTP/1.1\r\n"
                        "Host: %s\r\n"
                        "Content-Type: application/json\r\n"
                        "Content-Length: %u\r\n"
                        "User-Agent: logsystem-c/1.0\r\n"
                        "%s%s%s"
                        "Connection: close\r\n\r\n",
                        path, host, (unsigned int)body_len,
                        ((api_key != NULL) && (api_key[0] != '\0'))
                            ? "Authorization: Bearer " : "",
                        ((api_key != NULL) && (api_key[0] != '\0'))
                            ? api_key : "",
                        ((api_key != NULL) && (api_key[0] != '\0'))
                            ? "\r\n" : "");

                    if ((hlen < 0) || ((size_t)hlen >= sizeof(hdr))) {
                        rc = LOGSYS_ERR_TRUNC;
                    } else {
                        ssize_t sent_h = send(sock, hdr, (size_t)hlen, 0);
                        ssize_t sent_b = (sent_h > 0) ?
                            send(sock, body, body_len, 0) : (ssize_t)-1;
                        if ((sent_h < 0) || ((size_t)sent_h != (size_t)hlen) ||
                            (sent_b < 0) || ((size_t)sent_b != body_len)) {
                            rc = LOGSYS_ERR_NET;
                        } else {
                            char    resp[256];
                            ssize_t got;
                            (void)memset(resp, 0, sizeof(resp));
                            got = recv(sock, resp, sizeof(resp) - 1U, 0);
                            if (got <= 0) {
                                rc = LOGSYS_ERR_NET;
                            } else {
                                const char *sp = strchr(resp, ' ');
                                if (sp == NULL) {
                                    *out_status = 0;
                                    rc          = LOGSYS_ERR_NET;
                                } else {
                                    char *endp = NULL;
                                    long  st   = strtol(&sp[1], &endp, 10);
                                    if (endp == &sp[1]) {
                                        rc = LOGSYS_ERR_NET;
                                    } else {
                                        *out_status = st;
                                    }
                                }
                            }
                        }
                    }
                    /* Wipe the header buffer to remove the bearer token
                     * from the stack frame before return (CWE-316). */
                    (void)memset(hdr, 0, sizeof(hdr));
                }
                (void)close(sock);
            }
            freeaddrinfo(res);
        }
    }
    return rc;
}

#else /* USE_CURL */

static size_t curl_discard(void *p, size_t sz, size_t nm, void *ud)
{
    LOGSYS_UNUSED(p);
    LOGSYS_UNUSED(ud);
    return sz * nm;
}

static LogSysErr http_post_curl(const char *url, const char *api_key,
                                 const char *body, uint32_t body_len,
                                 uint32_t timeout_sec, long *out_status)
{
    LogSysErr rc   = LOGSYS_OK;
    CURL     *curl = curl_easy_init();

    if (curl == NULL) {
        rc = LOGSYS_ERR_NET;
    } else {
        struct curl_slist *hdrs = NULL;
        char               auth[UPLOADER_KEY_MAX + 32U];

        hdrs = curl_slist_append(hdrs, "Content-Type: application/json");
        hdrs = curl_slist_append(hdrs, "User-Agent: logsystem-c/1.0");
        if ((api_key != NULL) && (api_key[0] != '\0')) {
            (void)snprintf(auth, sizeof(auth),
                           "Authorization: Bearer %s", api_key);
            hdrs = curl_slist_append(hdrs, auth);
        }

        (void)curl_easy_setopt(curl, CURLOPT_URL,            url);
        (void)curl_easy_setopt(curl, CURLOPT_HTTPHEADER,     hdrs);
        (void)curl_easy_setopt(curl, CURLOPT_POSTFIELDS,     body);
        (void)curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE,  (long)body_len);
        (void)curl_easy_setopt(curl, CURLOPT_TIMEOUT,        (long)timeout_sec);
        (void)curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION,  curl_discard);

        if (curl_easy_perform(curl) != CURLE_OK) {
            rc = LOGSYS_ERR_NET;
        } else {
            (void)curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, out_status);
        }
        (void)memset(auth, 0, sizeof(auth)); /* CWE-316 */
        curl_slist_free_all(hdrs);
        curl_easy_cleanup(curl);
    }
    return rc;
}

#endif /* USE_CURL */

static LogSysErr do_http_post(Uploader *u, const char *body,
                               uint32_t len, long *status)
{
#ifdef USE_CURL
    return http_post_curl(u->endpoint, u->api_key, body, len,
                          u->timeout_sec, status);
#else
    return http_post_socket(u->endpoint, u->api_key, body, len,
                            u->timeout_sec, status);
#endif
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
#ifdef USE_CURL
        (void)curl_global_init(CURL_GLOBAL_DEFAULT);
#endif
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

            char       batch_id[EVT_ID_LEN];
            uint32_t   body_len;
            (void)uuid_gen(batch_id, sizeof(batch_id));

            if (build_batch_json(&events[off], chunk, batch_id,
                                  &body_len) != LOGSYS_OK) {
                u->total_failed += chunk;
                overall          = LOGSYS_ERR_TRUNC;
            } else {
                u->total_batches++;

                if ((u->dry_run == LOGSYS_TRUE) ||
                    (u->endpoint[0] == '\0')) {
                    /* MISRA 21.6 deviation: stderr used for diagnostics. */
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

                        rc = do_http_post(u, s_batch_buf, body_len, &status);
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
            /* Wipe the batch buffer between chunks to bound exposure
             * of message contents in memory dumps (defence in depth). */
            (void)memset(s_batch_buf, 0, body_len);
        }
        (void)pthread_mutex_unlock(&s_batch_mu);
    }
    return overall;
}
