/**
 * @file http_client.h
 * @brief Shared HTTP POST transport for uploader and monitor.
 *
 * Single implementation of URL parsing, socket setup, partial-send
 * handling, and response-status parsing — previously duplicated (and
 * already diverging) between uploader.c and monitor.c.
 *
 * Default backend: plain HTTP/1.1 over POSIX sockets (no dependencies).
 * Build with -DUSE_CURL and link -lcurl for HTTPS.
 *
 * Security:
 *   - Bearer token is placed only in the request header buffer, which
 *     is wiped before return (CWE-316).
 *   - Port range validated [1..65535] (CWE-20).
 *   - Partial send() handled by a bounded send-all loop (a truncated
 *     request can never be reported as success).
 */

#ifndef HTTP_CLIENT_H
#define HTTP_CLIENT_H

#include "logsys_types.h"

/**
 * POST body to url with optional bearer api_key.
 *
 * @param[out] out_status  HTTP status code (0 if none received).
 * @return LOGSYS_OK     request sent and a status line was parsed
 *         LOGSYS_ERR_*  parameter / network / truncation failure
 *
 * A LOGSYS_OK return does NOT imply 2xx — callers must check
 * *out_status.
 */
LogSysErr http_post(const char *url,
                    const char *api_key,
                    const char *body,
                    uint32_t    body_len,
                    uint32_t    timeout_sec,
                    long       *out_status);

#endif /* HTTP_CLIENT_H */
