/**
 * @file http_client.c
 * @brief Shared HTTP POST implementation (sockets, optional libcurl).
 */

#include "http_client.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>

#ifdef USE_CURL
#  include <curl/curl.h>
#  include <pthread.h>
#else
#  include <sys/socket.h>
#  include <netdb.h>
#  include <sys/time.h>
#endif

#ifndef USE_CURL

/* ------------------------------------------------------------------ */
/* URL parsing — single exit, strtol port validation (MISRA 21.7).    */
/* ------------------------------------------------------------------ */

static LogSysErr parse_url(const char *url,
                            char *host, uint32_t hcap,
                            int32_t *port,
                            char *path, uint32_t pcap)
{
    LogSysErr rc = LOGSYS_OK;

    if ((url == NULL) || (host == NULL) || (port == NULL) ||
        (path == NULL) || (hcap == 0U) || (pcap == 0U)) {
        rc = LOGSYS_ERR_PARAM;
    } else if (strncmp(url, "http://", 7U) != 0) {
        rc = LOGSYS_ERR_PARAM;     /* https requires USE_CURL build */
    } else {
        const char *p     = &url[7];
        const char *slash = strchr(p, '/');
        const char *colon = strchr(p, ':');
        ptrdiff_t   hlen;
        int         n;

        *port = 80;
        if (slash != NULL) {
            n = snprintf(path, (size_t)pcap, "%s", slash);
            hlen = ((colon != NULL) && (colon < slash))
                       ? (colon - p) : (slash - p);
        } else {
            n = snprintf(path, (size_t)pcap, "%s", "/");
            hlen = (colon != NULL) ? (colon - p)
                                   : (ptrdiff_t)strlen(p);
        }
        if ((n < 0) || ((uint32_t)n >= pcap)) {
            rc = LOGSYS_ERR_TRUNC;
        } else if ((hlen <= 0) || ((uint32_t)hlen >= hcap)) {
            rc = LOGSYS_ERR_TRUNC;
        } else {
            n = snprintf(host, (size_t)hcap, "%.*s", (int)hlen, p);
            if ((n < 0) || ((uint32_t)n >= hcap)) {
                rc = LOGSYS_ERR_TRUNC;
            } else if ((colon != NULL) &&
                       ((slash == NULL) || (colon < slash))) {
                char      *endp = NULL;
                const long pv   = strtol(&colon[1], &endp, 10);
                if ((endp == &colon[1]) ||
                    (pv < (long)LOGSYS_PORT_MIN) ||
                    (pv > (long)LOGSYS_PORT_MAX)) {
                    rc = LOGSYS_ERR_PARAM;
                } else {
                    *port = (int32_t)pv;
                }
            } else {
                /* no explicit port — default 80 stands */
            }
        }
    }
    return rc;
}

/* ------------------------------------------------------------------ */
/* send-all: handles partial send() (CWE: truncated request != ok).   */
/* Bounded: each iteration must make progress or we abort.            */
/* ------------------------------------------------------------------ */

static LogSysErr send_all(int sock, const char *buf, size_t len)
{
    LogSysErr rc   = LOGSYS_OK;
    size_t    sent = 0U;

    while ((sent < len) && (rc == LOGSYS_OK)) {
        const ssize_t w = send(sock, &buf[sent], len - sent, 0);
        if (w <= 0) {
            rc = LOGSYS_ERR_NET;
        } else {
            sent += (size_t)w;
        }
    }
    return rc;
}

static LogSysErr post_socket(const char *url, const char *api_key,
                              const char *body, uint32_t body_len,
                              uint32_t timeout_sec, long *out_status)
{
    LogSysErr rc = LOGSYS_OK;
    char      host[256];
    char      path[256];
    int32_t   port;

    rc = parse_url(url, host, sizeof(host), &port, path, sizeof(path));
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
                tv.tv_sec  = (time_t)timeout_sec;
                tv.tv_usec = 0;

                if ((setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO,
                                &tv, sizeof(tv)) != 0) ||
                    (setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO,
                                &tv, sizeof(tv)) != 0) ||
                    (connect(sock, res->ai_addr, res->ai_addrlen) != 0)) {
                    rc = LOGSYS_ERR_NET;
                } else {
                    char hdr[1024];
                    const bool_t have_key =
                        ((api_key != NULL) && (api_key[0] != '\0'))
                            ? LOGSYS_TRUE : LOGSYS_FALSE;
                    int hlen = snprintf(hdr, sizeof(hdr),
                        "POST %s HTTP/1.1\r\n"
                        "Host: %s\r\n"
                        "Content-Type: application/json\r\n"
                        "Content-Length: %u\r\n"
                        "User-Agent: logsystem-c/1.0\r\n"
                        "%s%s%s"
                        "Connection: close\r\n\r\n",
                        path, host, (unsigned int)body_len,
                        (have_key == LOGSYS_TRUE)
                            ? "Authorization: Bearer " : "",
                        (have_key == LOGSYS_TRUE) ? api_key : "",
                        (have_key == LOGSYS_TRUE) ? "\r\n" : "");

                    if ((hlen < 0) || ((size_t)hlen >= sizeof(hdr))) {
                        rc = LOGSYS_ERR_TRUNC;
                    } else {
                        rc = send_all(sock, hdr, (size_t)hlen);
                        if (rc == LOGSYS_OK) {
                            rc = send_all(sock, body, (size_t)body_len);
                        }
                        if (rc == LOGSYS_OK) {
                            char    resp[256];
                            ssize_t got;
                            (void)memset(resp, 0, sizeof(resp));
                            got = recv(sock, resp, sizeof(resp) - 1U, 0);
                            if (got <= 0) {
                                rc = LOGSYS_ERR_NET;
                            } else {
                                const char *sp = strchr(resp, ' ');
                                char       *endp = NULL;
                                long        st   = 0L;
                                if (sp != NULL) {
                                    st = strtol(&sp[1], &endp, 10);
                                }
                                if ((sp == NULL) || (endp == &sp[1])) {
                                    rc = LOGSYS_ERR_NET;
                                } else {
                                    *out_status = st;
                                }
                            }
                        }
                    }
                    /* Wipe the bearer token from the stack (CWE-316). */
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

/* Bound for the Authorization header buffer (mirrors uploader.h). */
#ifndef HTTP_KEY_MAX
#  define HTTP_KEY_MAX (256U)
#endif

static size_t curl_discard(void *p, size_t sz, size_t nm, void *ud)
{
    LOGSYS_UNUSED(p);
    LOGSYS_UNUSED(ud);
    return sz * nm;
}

/* curl_global_init must run exactly once (and was previously never
 * paired with cleanup); pthread_once gives a race-free single init. */
static pthread_once_t s_curl_once = PTHREAD_ONCE_INIT;

static void curl_init_once(void)
{
    (void)curl_global_init(CURL_GLOBAL_DEFAULT);
    (void)atexit(curl_global_cleanup);
}

static LogSysErr post_curl(const char *url, const char *api_key,
                            const char *body, uint32_t body_len,
                            uint32_t timeout_sec, long *out_status)
{
    LogSysErr rc;
    CURL     *curl;

    (void)pthread_once(&s_curl_once, curl_init_once);
    curl = curl_easy_init();

    if (curl == NULL) {
        rc = LOGSYS_ERR_NET;
    } else {
        struct curl_slist *hdrs = NULL;
        char               auth[HTTP_KEY_MAX + 32U];

        rc   = LOGSYS_OK;
        hdrs = curl_slist_append(hdrs, "Content-Type: application/json");
        hdrs = curl_slist_append(hdrs, "User-Agent: logsystem-c/1.0");
        if ((api_key != NULL) && (api_key[0] != '\0')) {
            (void)snprintf(auth, sizeof(auth),
                           "Authorization: Bearer %s", api_key);
            hdrs = curl_slist_append(hdrs, auth);
        }

        (void)curl_easy_setopt(curl, CURLOPT_URL,           url);
        (void)curl_easy_setopt(curl, CURLOPT_HTTPHEADER,    hdrs);
        (void)curl_easy_setopt(curl, CURLOPT_POSTFIELDS,    body);
        (void)curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)body_len);
        (void)curl_easy_setopt(curl, CURLOPT_TIMEOUT,       (long)timeout_sec);
        (void)curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_discard);

        if (curl_easy_perform(curl) != CURLE_OK) {
            rc = LOGSYS_ERR_NET;
        } else {
            (void)curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE,
                                    out_status);
        }
        (void)memset(auth, 0, sizeof(auth));    /* CWE-316 */
        curl_slist_free_all(hdrs);
        curl_easy_cleanup(curl);
    }
    return rc;
}

#endif /* USE_CURL */

/* ------------------------------------------------------------------ */
/* Public API                                                          */
/* ------------------------------------------------------------------ */

LogSysErr http_post(const char *url,
                    const char *api_key,
                    const char *body,
                    uint32_t    body_len,
                    uint32_t    timeout_sec,
                    long       *out_status)
{
    LogSysErr rc;

    if ((url == NULL) || (body == NULL) || (out_status == NULL)) {
        rc = LOGSYS_ERR_PARAM;
    } else {
        *out_status = 0L;
#ifdef USE_CURL
        rc = post_curl(url, api_key, body, body_len,
                       timeout_sec, out_status);
#else
        rc = post_socket(url, api_key, body, body_len,
                         timeout_sec, out_status);
#endif
    }
    return rc;
}
