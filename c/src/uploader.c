/*
 * uploader.c — batch HTTP/1.1 POST with exponential-backoff retry.
 *
 * Default: plain HTTP via POSIX sockets (no extra dependencies).
 * Compile with -DUSE_CURL and link -lcurl for HTTPS and more robust HTTP.
 */

#include "uploader.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <stdint.h>

#ifdef USE_CURL
#  include <curl/curl.h>
#else
#  include <sys/socket.h>
#  include <netdb.h>
#  include <sys/time.h>
#endif

/* ------------------------------------------------------------------ */
/* JSON batch serialisation                                            */
/* ------------------------------------------------------------------ */

/* Generous upper bound per event: message (×2 for escaping) + overhead */
#define PER_EVT_BUDGET (EVT_MSG_MAX * 2 + 512)
#define BATCH_JSON_MAX (UPLOADER_BATCH_MAX * PER_EVT_BUDGET + 256)

static char *build_batch_json(const LogEvent *events, size_t count,
                               const char *batch_id, size_t *out_len) {
    char *buf = malloc(BATCH_JSON_MAX);
    if (!buf) return NULL;

    struct timespec now;
    clock_gettime(CLOCK_REALTIME, &now);
    char ts[32];
    ts_iso8601(&now, ts, sizeof(ts));

    int n = snprintf(buf, BATCH_JSON_MAX,
        "{\"batch_id\":\"%s\",\"created_at\":\"%s\","
        "\"event_count\":%zu,\"events\":[",
        batch_id, ts, count);

    for (size_t i = 0; i < count && n < BATCH_JSON_MAX - 16; i++) {
        char evj[PER_EVT_BUDGET];
        evt_to_json(&events[i], evj, sizeof(evj));
        n += snprintf(buf+n, (size_t)(BATCH_JSON_MAX-n),
                      "%s%s", i ? "," : "", evj);
    }
    n += snprintf(buf+n, (size_t)(BATCH_JSON_MAX-n), "]}");
    *out_len = (size_t)n;
    return buf;
}

/* ------------------------------------------------------------------ */
/* HTTP transport — plain sockets                                      */
/* ------------------------------------------------------------------ */

#ifndef USE_CURL

/* Parse http://host[:port]/path — returns 0 on success */
static int parse_url(const char *url,
                     char *host, size_t hcap,
                     int  *port,
                     char *path, size_t pcap) {
    if (strncmp(url, "http://", 7) != 0) {
        fprintf(stderr, "[uploader] Only http:// supported without USE_CURL\n");
        return -1;
    }
    const char *p = url + 7;
    const char *slash = strchr(p, '/');
    const char *colon = strchr(p, ':');

    *port = 80;
    if (slash) {
        snprintf(path, pcap, "%s", slash);
        if (colon && colon < slash) {
            snprintf(host, hcap, "%.*s", (int)(colon - p), p);
            *port = atoi(colon + 1);
        } else {
            snprintf(host, hcap, "%.*s", (int)(slash - p), p);
        }
    } else {
        snprintf(path, pcap, "/");
        snprintf(host, hcap, "%s", p);
    }
    return 0;
}

static int http_post_socket(const char *url, const char *api_key,
                             const char *body, size_t body_len,
                             double timeout_sec, long *out_status) {
    char host[256], path[512];
    int  port;
    if (parse_url(url, host, sizeof(host), &port, path, sizeof(path)) < 0)
        return -1;

    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    char port_str[8];
    snprintf(port_str, sizeof(port_str), "%d", port);
    if (getaddrinfo(host, port_str, &hints, &res) != 0) return -1;

    int sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (sock < 0) { freeaddrinfo(res); return -1; }

    int to_sec = (int)timeout_sec;
    struct timeval tv = { .tv_sec = to_sec > 0 ? to_sec : 10, .tv_usec = 0 };
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    if (connect(sock, res->ai_addr, res->ai_addrlen) < 0) {
        freeaddrinfo(res); close(sock); return -1;
    }
    freeaddrinfo(res);

    /* Build request */
    char hdr[1024];
    int hlen = snprintf(hdr, sizeof(hdr),
        "POST %s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: %zu\r\n"
        "User-Agent: logsystem-c/1.0\r\n"
        "%s%s%s"
        "Connection: close\r\n\r\n",
        path, host, body_len,
        api_key[0] ? "Authorization: Bearer " : "",
        api_key[0] ? api_key : "",
        api_key[0] ? "\r\n" : "");

    if (send(sock, hdr,  (size_t)hlen, 0) < 0 ||
        send(sock, body, body_len,     0) < 0) {
        close(sock); return -1;
    }

    /* Read just enough to get the status line */
    char resp[256] = {0};
    recv(sock, resp, sizeof(resp)-1, 0);
    close(sock);

    if (out_status) {
        const char *sp = strchr(resp, ' ');
        *out_status = sp ? atol(sp+1) : 0;
    }
    return 0;
}

#else /* USE_CURL */

/* libcurl keeps response body we don't need — discard it */
static size_t curl_discard(void *p, size_t sz, size_t nm, void *ud) {
    (void)p; (void)ud;
    return sz * nm;
}

static int http_post_curl(const char *url, const char *api_key,
                           const char *body, size_t body_len,
                           double timeout_sec, long *out_status) {
    CURL *curl = curl_easy_init();
    if (!curl) return -1;

    struct curl_slist *hdrs = NULL;
    hdrs = curl_slist_append(hdrs, "Content-Type: application/json");
    hdrs = curl_slist_append(hdrs, "User-Agent: logsystem-c/1.0");

    if (api_key[0]) {
        char auth[UPLOADER_KEY_MAX + 32];
        snprintf(auth, sizeof(auth), "Authorization: Bearer %s", api_key);
        hdrs = curl_slist_append(hdrs, auth);
    }

    curl_easy_setopt(curl, CURLOPT_URL,            url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER,     hdrs);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS,     body);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE,  (long)body_len);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT,        (long)timeout_sec);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION,  curl_discard);

    CURLcode rc = curl_easy_perform(curl);
    int ret = 0;
    if (rc != CURLE_OK) {
        fprintf(stderr, "[uploader] curl error: %s\n", curl_easy_strerror(rc));
        ret = -1;
    } else if (out_status) {
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, out_status);
    }
    curl_slist_free_all(hdrs);
    curl_easy_cleanup(curl);
    return ret;
}

#endif /* USE_CURL */

/* Unified send — returns 0 and sets *status on success, -1 on I/O error */
static int do_http_post(Uploader *u, const char *body, size_t len, long *status) {
#ifdef USE_CURL
    return http_post_curl(u->endpoint, u->api_key, body, len, u->timeout_sec, status);
#else
    return http_post_socket(u->endpoint, u->api_key, body, len, u->timeout_sec, status);
#endif
}

/* ------------------------------------------------------------------ */
/* Retry logic                                                         */
/* ------------------------------------------------------------------ */

static int is_retryable(long status) {
    return (status == 429 || status == 500 ||
            status == 502 || status == 503 || status == 504);
}

static void sleep_sec(double s) {
    struct timespec ts = {
        .tv_sec  = (time_t)s,
        .tv_nsec = (long)((s - (time_t)s) * 1e9)
    };
    nanosleep(&ts, NULL);
}

/* ------------------------------------------------------------------ */
/* Public API                                                          */
/* ------------------------------------------------------------------ */

void uploader_init(Uploader *u) {
    memset(u, 0, sizeof(*u));
    u->retry_attempts = 4;
    u->backoff_sec    = 2.0;
    u->timeout_sec    = 10.0;
    u->dry_run        = 0;
#ifdef USE_CURL
    curl_global_init(CURL_GLOBAL_DEFAULT);
#endif
}

int uploader_send(Uploader *u, const LogEvent *events, size_t count) {
    if (count == 0) return 0;

    /* Split into chunks of UPLOADER_BATCH_MAX */
    int overall = 0;
    for (size_t off = 0; off < count; off += UPLOADER_BATCH_MAX) {
        size_t chunk = count - off;
        if (chunk > UPLOADER_BATCH_MAX) chunk = UPLOADER_BATCH_MAX;

        char batch_id[EVT_ID_LEN];
        uuid_gen(batch_id);

        size_t body_len;
        char *body = build_batch_json(events + off, chunk, batch_id, &body_len);
        if (!body) { u->total_failed += chunk; continue; }

        u->total_batches++;

        if (u->dry_run || u->endpoint[0] == '\0') {
            fprintf(stderr, "[uploader] DRY-RUN batch=%.*s events=%zu\n",
                    8, batch_id, chunk);
            u->total_sent += chunk;
            free(body);
            continue;
        }

        double delay = u->backoff_sec;
        int sent = 0;
        for (int attempt = 1; attempt <= u->retry_attempts; attempt++) {
            long status = 0;
            int rc = do_http_post(u, body, body_len, &status);

            if (rc == 0 && status >= 200 && status < 300) {
                u->total_sent += chunk;
                sent = 1;
                break;
            }

            int retry = (rc < 0) || is_retryable(status);
            fprintf(stderr, "[uploader] batch=%.*s attempt=%d status=%ld %s\n",
                    8, batch_id, attempt, status, retry ? "(retry)" : "(fatal)");

            if (!retry || attempt == u->retry_attempts) break;
            sleep_sec(delay);
            delay *= 2.0;
        }
        if (!sent) {
            u->total_failed += chunk;
            overall = -1;
        }
        free(body);
    }
    return overall;
}
