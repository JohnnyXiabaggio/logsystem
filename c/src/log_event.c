#include "log_event.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <ctype.h>

/* ------------------------------------------------------------------ */
/* Severity                                                            */
/* ------------------------------------------------------------------ */

const char *sev_label(Severity s) {
    switch (s) {
        case SEV_DEBUG:    return "DEBUG";
        case SEV_INFO:     return "INFO";
        case SEV_WARNING:  return "WARNING";
        case SEV_ERROR:    return "ERROR";
        case SEV_CRITICAL: return "CRITICAL";
        default:           return "INFO";
    }
}

Severity sev_detect(const char *line) {
    if (strcasestr(line, "critical") || strcasestr(line, "fatal"))
        return SEV_CRITICAL;
    if (strcasestr(line, "error"))
        return SEV_ERROR;
    if (strcasestr(line, "warn"))
        return SEV_WARNING;
    if (strcasestr(line, "debug"))
        return SEV_DEBUG;
    return SEV_INFO;
}

/* ------------------------------------------------------------------ */
/* UUID v4                                                             */
/* ------------------------------------------------------------------ */

void uuid_gen(char out[EVT_ID_LEN]) {
    uint8_t b[16];
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0 || read(fd, b, 16) != 16) {
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        uint64_t seed = (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
        for (int i = 0; i < 16; i++) {
            seed ^= seed << 13; seed ^= seed >> 7; seed ^= seed << 17;
            b[i] = (uint8_t)seed;
        }
    }
    if (fd >= 0) close(fd);

    b[6] = (b[6] & 0x0f) | 0x40;  /* version 4 */
    b[8] = (b[8] & 0x3f) | 0x80;  /* RFC 4122 variant */

    snprintf(out, EVT_ID_LEN,
        "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x"
        "-%02x%02x%02x%02x%02x%02x",
        b[0],b[1],b[2],b[3], b[4],b[5], b[6],b[7],
        b[8],b[9], b[10],b[11],b[12],b[13],b[14],b[15]);
}

/* ------------------------------------------------------------------ */
/* Timestamp                                                           */
/* ------------------------------------------------------------------ */

void ts_iso8601(const struct timespec *ts, char *buf, size_t cap) {
    struct tm t;
    gmtime_r(&ts->tv_sec, &t);
    snprintf(buf, cap, "%04d-%02d-%02dT%02d:%02d:%02d.%03ldZ",
             t.tm_year + 1900, t.tm_mon + 1, t.tm_mday,
             t.tm_hour, t.tm_min, t.tm_sec,
             ts->tv_nsec / 1000000L);
}

/* ------------------------------------------------------------------ */
/* JSON string escaping                                                */
/* ------------------------------------------------------------------ */

int json_escape(char *dst, size_t cap, const char *src) {
    size_t n = 0;
    if (n < cap) dst[n++] = '"';
    for (const char *p = src; *p && n + 8 < cap; p++) {
        unsigned char c = (unsigned char)*p;
        if      (c == '"')  { dst[n++] = '\\'; dst[n++] = '"';  }
        else if (c == '\\') { dst[n++] = '\\'; dst[n++] = '\\'; }
        else if (c == '\n') { dst[n++] = '\\'; dst[n++] = 'n';  }
        else if (c == '\r') { dst[n++] = '\\'; dst[n++] = 'r';  }
        else if (c == '\t') { dst[n++] = '\\'; dst[n++] = 't';  }
        else if (c < 0x20)  { n += (size_t)snprintf(dst+n, cap-n, "\\u%04x", c); }
        else dst[n++] = (char)c;
    }
    if (n < cap) dst[n++] = '"';
    if (n < cap) dst[n] = '\0';
    return (int)n;
}

/* ------------------------------------------------------------------ */
/* Event lifecycle                                                     */
/* ------------------------------------------------------------------ */

void evt_init(LogEvent *e, const char *msg, Severity sev, const char *src) {
    memset(e, 0, sizeof(*e));
    uuid_gen(e->id);
    clock_gettime(CLOCK_REALTIME, &e->ts);
    e->severity = sev;
    snprintf(e->source,  sizeof(e->source),  "%s", src ? src : "unknown");
    snprintf(e->message, sizeof(e->message), "%s", msg ? msg : "");
    e->ntags = 0;
}

void evt_add_tag(LogEvent *e, const char *k, const char *v) {
    if (e->ntags >= EVT_TAGS_MAX) return;
    snprintf(e->tags[e->ntags].k, TAG_KEY_MAX, "%s", k);
    snprintf(e->tags[e->ntags].v, TAG_VAL_MAX, "%s", v);
    e->ntags++;
}

int evt_to_json(const LogEvent *e, char *buf, size_t cap) {
    char ts[32], id_j[EVT_ID_LEN+4], src_j[EVT_SRC_MAX*2], msg_j[EVT_MSG_MAX*2];
    ts_iso8601(&e->ts, ts, sizeof(ts));
    json_escape(id_j,  sizeof(id_j),  e->id);
    json_escape(src_j, sizeof(src_j), e->source);
    json_escape(msg_j, sizeof(msg_j), e->message);

    int n = snprintf(buf, cap,
        "{\"event_id\":%s,\"timestamp\":\"%s\","
        "\"severity\":\"%s\",\"severity_code\":%d,"
        "\"source\":%s,\"message\":%s,\"tags\":{",
        id_j, ts, sev_label(e->severity), (int)e->severity,
        src_j, msg_j);

    for (int i = 0; i < e->ntags && n < (int)cap - 4; i++) {
        char kj[TAG_KEY_MAX+4], vj[TAG_VAL_MAX+4];
        json_escape(kj, sizeof(kj), e->tags[i].k);
        json_escape(vj, sizeof(vj), e->tags[i].v);
        n += snprintf(buf+n, cap-(size_t)n, "%s%s:%s", i ? "," : "", kj, vj);
    }
    n += snprintf(buf+n, cap-(size_t)n, "}}");
    return n;
}

int evt_from_line(const char *line, const char *src, LogEvent *out) {
    char clean[EVT_MSG_MAX];
    snprintf(clean, sizeof(clean), "%s", line);
    size_t len = strlen(clean);
    while (len > 0 && (clean[len-1] == '\n' || clean[len-1] == '\r'))
        clean[--len] = '\0';
    if (len == 0) return -1;

    evt_init(out, clean, sev_detect(clean), src);
    return 0;
}
