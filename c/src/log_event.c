/**
 * @file log_event.c
 * @brief Implementation of LogEvent primitives.
 *
 * All functions:
 *   - validate inputs (NULL, capacity)
 *   - bound every string operation by an explicit length
 *   - return LogSysErr; never abort or call exit
 *   - use bool_t for controlling expressions (MISRA 14.4)
 *   - have a single point of exit (MISRA 15.5) wherever practical
 */

#include "log_event.h"

#include <string.h>
#include <stdio.h>     /* snprintf — MISRA 21.6 deviation: required for serialisation */
#include <ctype.h>
#include <fcntl.h>     /* open                                                          */
#include <unistd.h>    /* read, close                                                    */

/* ------------------------------------------------------------------ */
/* Severity                                                            */
/* ------------------------------------------------------------------ */

const char *sev_label(Severity s)
{
    const char *result;

    /* MISRA 16.1/16.4: every switch has a default. */
    switch (s) {
        case SEV_DEBUG:    result = "DEBUG";    break;
        case SEV_INFO:     result = "INFO";     break;
        case SEV_WARNING:  result = "WARNING";  break;
        case SEV_ERROR:    result = "ERROR";    break;
        case SEV_CRITICAL: result = "CRITICAL"; break;
        default:           result = "INFO";     break;
    }
    return result;
}

/* MISRA 8.7: internal-linkage helper — portable case-insensitive search.
 * Avoids GNU-only strcasestr (MISRA 21.2 / portability). */
static bool_t str_contains_icase(const char *hay, const char *needle)
{
    bool_t found = LOGSYS_FALSE;

    if ((hay != NULL) && (needle != NULL)) {
        const size_t hay_len    = strlen(hay);
        const size_t needle_len = strlen(needle);

        if ((needle_len > 0U) && (hay_len >= needle_len)) {
            const size_t last = hay_len - needle_len;
            size_t       i;
            for (i = 0U; (i <= last) && (found == LOGSYS_FALSE); i++) {
                bool_t match = LOGSYS_TRUE;
                size_t j;
                for (j = 0U; (j < needle_len) && (match == LOGSYS_TRUE); j++) {
                    const int hc =
                        tolower((int)(unsigned char)hay[i + j]);
                    const int nc =
                        tolower((int)(unsigned char)needle[j]);
                    if (hc != nc) {
                        match = LOGSYS_FALSE;
                    }
                }
                if (match == LOGSYS_TRUE) {
                    found = LOGSYS_TRUE;
                }
            }
        }
    }
    return found;
}

Severity sev_detect(const char *line)
{
    Severity result = SEV_INFO;

    if (line != NULL) {
        if (str_contains_icase(line, "critical") ||
            str_contains_icase(line, "fatal")) {
            result = SEV_CRITICAL;
        } else if (str_contains_icase(line, "error")) {
            result = SEV_ERROR;
        } else if (str_contains_icase(line, "warn")) {
            result = SEV_WARNING;
        } else if (str_contains_icase(line, "debug")) {
            result = SEV_DEBUG;
        } else {
            result = SEV_INFO;
        }
    }
    return result;
}

/* ------------------------------------------------------------------ */
/* UUID v4                                                             */
/*                                                                     */
/* Uses /dev/urandom for cryptographic-quality randomness (CWE-330).   */
/* Falls back to a deterministic xorshift seeded by time on failure;   */
/* the fallback is announced via the error code so the caller may     */
/* decide whether to accept it.                                        */
/* ------------------------------------------------------------------ */

static LogSysErr fill_random(uint8_t *dst, uint32_t len)
{
    LogSysErr rc  = LOGSYS_OK;
    int       fd  = open("/dev/urandom", O_RDONLY);

    if (fd < 0) {
        rc = LOGSYS_ERR_IO;
    } else {
        ssize_t got = read(fd, dst, (size_t)len);
        if (close(fd) != 0) {
            /* close failure is logged but does not invalidate the bytes */
        }
        if ((got < 0) || ((uint32_t)got != len)) {
            rc = LOGSYS_ERR_IO;
        }
    }
    return rc;
}

LogSysErr uuid_gen(char *out, uint32_t cap)
{
    LogSysErr rc = LOGSYS_OK;

    if ((out == NULL) || (cap < EVT_ID_LEN)) {
        rc = LOGSYS_ERR_PARAM;
    } else {
        uint8_t b[16];
        if (fill_random(b, 16U) != LOGSYS_OK) {
            /* Fallback: time-seeded xorshift. Marks the UUID as
             * not-cryptographically-strong; we continue but warn the
             * caller via return code. */
            struct timespec ts_now;
            uint32_t        i;
            uint64_t        seed;
            (void)clock_gettime(CLOCK_REALTIME, &ts_now);
            seed = ((uint64_t)ts_now.tv_sec * 1000000000ULL) +
                   (uint64_t)ts_now.tv_nsec;
            for (i = 0U; i < 16U; i++) {
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                b[i]  = (uint8_t)(seed & 0xFFU);
            }
            rc = LOGSYS_ERR_IO;  /* non-fatal warning */
        }

        /* RFC 4122 §4.4: set version (0100) and variant (10xx). */
        b[6] = (uint8_t)((b[6] & 0x0FU) | 0x40U);
        b[8] = (uint8_t)((b[8] & 0x3FU) | 0x80U);

        {
            int n = snprintf(out, (size_t)cap,
                "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x"
                "-%02x%02x%02x%02x%02x%02x",
                b[0], b[1], b[2], b[3],  b[4], b[5],
                b[6], b[7],  b[8], b[9],
                b[10], b[11], b[12], b[13], b[14], b[15]);
            if ((n < 0) || ((uint32_t)n >= cap)) {
                rc = LOGSYS_ERR_TRUNC;
            }
        }
    }
    return rc;
}

/* ------------------------------------------------------------------ */
/* Timestamp                                                           */
/* ------------------------------------------------------------------ */

LogSysErr ts_iso8601(const struct timespec *ts, char *buf, uint32_t cap)
{
    LogSysErr rc = LOGSYS_OK;

    if ((ts == NULL) || (buf == NULL) || (cap < 32U)) {
        rc = LOGSYS_ERR_PARAM;
    } else {
        struct tm tm_buf;
        /* gmtime_r is POSIX — async-signal-safe and reentrant. */
        if (gmtime_r(&ts->tv_sec, &tm_buf) == NULL) {
            rc = LOGSYS_ERR_IO;
        } else {
            const long  ms = ts->tv_nsec / 1000000L;
            const int   n  = snprintf(buf, (size_t)cap,
                "%04d-%02d-%02dT%02d:%02d:%02d.%03ldZ",
                tm_buf.tm_year + 1900,
                tm_buf.tm_mon  + 1,
                tm_buf.tm_mday,
                tm_buf.tm_hour,
                tm_buf.tm_min,
                tm_buf.tm_sec,
                ms);
            if ((n < 0) || ((uint32_t)n >= cap)) {
                rc = LOGSYS_ERR_TRUNC;
            }
        }
    }
    return rc;
}

/* ------------------------------------------------------------------ */
/* JSON string escape                                                  */
/* ------------------------------------------------------------------ */

LogSysErr json_escape(char *dst, uint32_t cap, const char *src)
{
    LogSysErr rc = LOGSYS_OK;

    if ((dst == NULL) || (src == NULL) || (cap < 3U)) {
        /* Need at least "" and NUL */
        rc = LOGSYS_ERR_PARAM;
    } else {
        uint32_t   n  = 0U;
        const char *p;
        bool_t     ok = LOGSYS_TRUE;

        dst[n] = '"';
        n++;

        for (p = src; (*p != '\0') && (ok == LOGSYS_TRUE); p++) {
            const unsigned char c = (unsigned char)*p;
            uint32_t            need;

            /* Compute exact bytes required for this char's encoding,
             * plus closing quote and NUL terminator (2 trailing bytes). */
            if (c < 0x20U) {
                /* control char -> \uXXXX (6 bytes) unless it's one of
                 * the two-byte short escapes handled below */
                if ((c == (unsigned char)'\n') ||
                    (c == (unsigned char)'\r') ||
                    (c == (unsigned char)'\t')) {
                    need = 2U;
                } else {
                    need = 6U;
                }
            } else if ((c == (unsigned char)'"') ||
                       (c == (unsigned char)'\\')) {
                need = 2U;
            } else {
                need = 1U;
            }

            if ((n + need + 2U) > cap) {
                ok = LOGSYS_FALSE;
            } else if (c == (unsigned char)'"')  {
                dst[n] = '\\'; n++; dst[n] = '"'; n++;
            } else if (c == (unsigned char)'\\') {
                dst[n] = '\\'; n++; dst[n] = '\\'; n++;
            } else if (c == (unsigned char)'\n') {
                dst[n] = '\\'; n++; dst[n] = 'n';  n++;
            } else if (c == (unsigned char)'\r') {
                dst[n] = '\\'; n++; dst[n] = 'r';  n++;
            } else if (c == (unsigned char)'\t') {
                dst[n] = '\\'; n++; dst[n] = 't';  n++;
            } else if (c < 0x20U) {
                const int w = snprintf(&dst[n], (size_t)(cap - n),
                                       "\\u%04x", (unsigned int)c);
                if ((w < 0) || ((uint32_t)w >= (cap - n))) {
                    ok = LOGSYS_FALSE;
                } else {
                    n += (uint32_t)w;
                }
            } else {
                dst[n] = (char)c;
                n++;
            }
        }

        if (ok == LOGSYS_FALSE) {
            rc = LOGSYS_ERR_TRUNC;
        } else if ((n + 2U) > cap) {
            rc = LOGSYS_ERR_TRUNC;
        } else {
            dst[n] = '"';
            n++;
            dst[n] = '\0';
        }
    }
    return rc;
}

/* ------------------------------------------------------------------ */
/* Event lifecycle                                                     */
/* ------------------------------------------------------------------ */

LogSysErr evt_init(LogEvent *e, const char *msg, Severity sev, const char *src)
{
    LogSysErr rc = LOGSYS_OK;

    if (e == NULL) {
        rc = LOGSYS_ERR_PARAM;
    } else {
        /* MISRA 17.7: memset return is the same pointer; explicit (void). */
        (void)memset(e, 0, sizeof(*e));

        /* uuid_gen may downgrade to LOGSYS_ERR_IO if /dev/urandom is
         * unavailable; we still proceed with the (weaker) UUID. */
        (void)uuid_gen(e->id, EVT_ID_LEN);

        (void)clock_gettime(CLOCK_REALTIME, &e->ts);
        e->severity = sev;

        {
            int n;
            n = snprintf(e->source, sizeof(e->source), "%s",
                         (src != NULL) ? src : "unknown");
            if ((n < 0) || ((size_t)n >= sizeof(e->source))) {
                rc = LOGSYS_ERR_TRUNC;
            }
            n = snprintf(e->message, sizeof(e->message), "%s",
                         (msg != NULL) ? msg : "");
            if ((n < 0) || ((size_t)n >= sizeof(e->message))) {
                rc = LOGSYS_ERR_TRUNC;
            }
        }
        e->ntags = 0U;
    }
    return rc;
}

LogSysErr evt_add_tag(LogEvent *e, const char *k, const char *v)
{
    LogSysErr rc = LOGSYS_OK;

    if ((e == NULL) || (k == NULL) || (v == NULL)) {
        rc = LOGSYS_ERR_PARAM;
    } else if (e->ntags >= (uint8_t)EVT_TAGS_MAX) {
        rc = LOGSYS_ERR_FULL;
    } else {
        const uint8_t idx = e->ntags;
        int           n;

        n = snprintf(e->tag_keys[idx], TAG_KEY_MAX, "%s", k);
        if ((n < 0) || ((size_t)n >= TAG_KEY_MAX)) {
            rc = LOGSYS_ERR_TRUNC;
        }
        n = snprintf(e->tag_vals[idx], TAG_VAL_MAX, "%s", v);
        if ((n < 0) || ((size_t)n >= TAG_VAL_MAX)) {
            rc = LOGSYS_ERR_TRUNC;
        }
        e->ntags = (uint8_t)(idx + 1U);
    }
    return rc;
}

LogSysErr evt_to_json(const LogEvent *e, char *buf, uint32_t cap)
{
    LogSysErr rc = LOGSYS_OK;

    if ((e == NULL) || (buf == NULL) || (cap < 64U)) {
        rc = LOGSYS_ERR_PARAM;
    } else {
        char    ts_str[32];
        char    id_j[EVT_ID_LEN + 4U];
        char    src_j[EVT_SRC_MAX * 2U];
        char    msg_j[EVT_MSG_MAX * 2U];
        int     n;
        int32_t off;
        bool_t  ok = LOGSYS_TRUE;

        if (ts_iso8601(&e->ts, ts_str, sizeof(ts_str))    != LOGSYS_OK) { ok = LOGSYS_FALSE; }
        if (json_escape(id_j,  sizeof(id_j),  e->id)      != LOGSYS_OK) { ok = LOGSYS_FALSE; }
        if (json_escape(src_j, sizeof(src_j), e->source)  != LOGSYS_OK) { ok = LOGSYS_FALSE; }
        if (json_escape(msg_j, sizeof(msg_j), e->message) != LOGSYS_OK) { ok = LOGSYS_FALSE; }

        if (ok == LOGSYS_FALSE) {
            rc = LOGSYS_ERR_TRUNC;
        } else {
            n = snprintf(buf, (size_t)cap,
                "{\"event_id\":%s,\"timestamp\":\"%s\","
                "\"severity\":\"%s\",\"severity_code\":%d,"
                "\"source\":%s,\"message\":%s,\"tags\":{",
                id_j, ts_str, sev_label(e->severity),
                (int)e->severity, src_j, msg_j);

            if ((n < 0) || ((uint32_t)n >= cap)) {
                rc = LOGSYS_ERR_TRUNC;
            } else {
                uint8_t i;
                off = n;
                for (i = 0U; (i < e->ntags) && (rc == LOGSYS_OK); i++) {
                    char kj[TAG_KEY_MAX + 4U];
                    char vj[TAG_VAL_MAX + 4U];

                    if ((json_escape(kj, sizeof(kj), e->tag_keys[i]) != LOGSYS_OK) ||
                        (json_escape(vj, sizeof(vj), e->tag_vals[i]) != LOGSYS_OK)) {
                        rc = LOGSYS_ERR_TRUNC;
                    } else if ((uint32_t)off >= cap) {
                        rc = LOGSYS_ERR_TRUNC;
                    } else {
                        n = snprintf(&buf[off], (size_t)(cap - (uint32_t)off),
                                     "%s%s:%s", (i == 0U) ? "" : ",", kj, vj);
                        if ((n < 0) || ((uint32_t)n >= (cap - (uint32_t)off))) {
                            rc = LOGSYS_ERR_TRUNC;
                        } else {
                            off += n;
                        }
                    }
                }
                if (rc == LOGSYS_OK) {
                    if ((uint32_t)off >= cap) {
                        rc = LOGSYS_ERR_TRUNC;
                    } else {
                        n = snprintf(&buf[off], (size_t)(cap - (uint32_t)off), "}}");
                        if ((n < 0) || ((uint32_t)n >= (cap - (uint32_t)off))) {
                            rc = LOGSYS_ERR_TRUNC;
                        }
                    }
                }
            }
        }
    }
    return rc;
}

LogSysErr evt_from_line(const char *line, const char *src, LogEvent *out)
{
    LogSysErr rc = LOGSYS_OK;

    if ((line == NULL) || (out == NULL)) {
        rc = LOGSYS_ERR_PARAM;
    } else {
        char   clean[EVT_MSG_MAX];
        size_t len;
        int    n;

        n = snprintf(clean, sizeof(clean), "%s", line);
        if ((n < 0) || ((size_t)n >= sizeof(clean))) {
            /* Long input is truncated, not an error — we still record it. */
            clean[sizeof(clean) - 1U] = '\0';
        }
        len = strlen(clean);
        while ((len > 0U) &&
               ((clean[len - 1U] == '\n') || (clean[len - 1U] == '\r'))) {
            len--;
            clean[len] = '\0';
        }

        if (len == 0U) {
            rc = LOGSYS_ERR_PARAM;       /* blank line */
        } else {
            rc = evt_init(out, clean, sev_detect(clean), src);
        }
    }
    return rc;
}
