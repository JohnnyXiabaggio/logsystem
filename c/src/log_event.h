/**
 * @file log_event.h
 * @brief Log event model, severity classification, and JSON serialisation.
 *
 * Compliance:
 *   - MISRA C:2012 (Rules 8.2, 8.4, 8.7, 10.1, 17.4, 17.7)
 *   - IEC 61508: no dynamic memory; all storage is caller-owned
 *   - CWE-120: every string operation is bounded by an explicit length
 */

#ifndef LOG_EVENT_H
#define LOG_EVENT_H

#include "logsys_types.h"
#include <time.h>      /* struct timespec — POSIX 1003.1-2008 */

/* ------------------------------------------------------------------ */
/* Compile-time sizes                                                  */
/* ------------------------------------------------------------------ */
#define EVT_MSG_MAX   (512U)
#define EVT_SRC_MAX   (128U)
#define EVT_ID_LEN    (37U)   /* UUID v4: 36 chars + NUL */
#define EVT_TAGS_MAX  (4U)
#define TAG_KEY_MAX   (32U)
#define TAG_VAL_MAX   (64U)

/* Worst-case JSON encoding budget (every byte escaped, plus overhead). */
#define EVT_JSON_MAX  ((EVT_MSG_MAX * 2U) + (EVT_SRC_MAX * 2U) + 256U)

LOGSYS_STATIC_ASSERT(EVT_MSG_MAX  >= 16U,  evt_msg_min);
LOGSYS_STATIC_ASSERT(EVT_ID_LEN   == 37U,  evt_id_exact);
LOGSYS_STATIC_ASSERT(EVT_TAGS_MAX <= 255U, evt_tags_fits_u8);

/* ------------------------------------------------------------------ */
/* Severity                                                            */
/* ------------------------------------------------------------------ */
typedef enum {
    SEV_DEBUG    = 10,
    SEV_INFO     = 20,
    SEV_WARNING  = 30,
    SEV_ERROR    = 40,
    SEV_CRITICAL = 50
} Severity;

/* ------------------------------------------------------------------ */
/* Event structure (POD — copyable by assignment)                     */
/* ------------------------------------------------------------------ */
typedef struct {
    char            id[EVT_ID_LEN];
    struct timespec ts;
    Severity        severity;
    char            source[EVT_SRC_MAX];
    char            message[EVT_MSG_MAX];
    char            tag_keys[EVT_TAGS_MAX][TAG_KEY_MAX];
    char            tag_vals[EVT_TAGS_MAX][TAG_VAL_MAX];
    uint8_t         ntags;     /* MISRA 10.1: range 0..EVT_TAGS_MAX */
} LogEvent;

/* ------------------------------------------------------------------ */
/* Severity helpers                                                    */
/* ------------------------------------------------------------------ */
const char *sev_label(Severity s);
Severity    sev_detect(const char *line);

/* ------------------------------------------------------------------ */
/* Utility primitives — shared by other modules                       */
/* ------------------------------------------------------------------ */

/**
 * Generate a UUID v4 string into the caller-supplied buffer.
 * Buffer must be at least EVT_ID_LEN bytes.
 * @return LOGSYS_OK or LOGSYS_ERR_PARAM (NULL out / cap too small).
 */
LogSysErr uuid_gen(char *out, uint32_t cap);

/**
 * Format a POSIX timespec as ISO-8601 UTC ("YYYY-MM-DDTHH:MM:SS.mmmZ").
 * @return LOGSYS_OK / LOGSYS_ERR_PARAM / LOGSYS_ERR_TRUNC.
 */
LogSysErr ts_iso8601(const struct timespec *ts, char *buf, uint32_t cap);

/**
 * Write src to dst as a double-quoted, JSON-escaped string.
 * Output is always NUL-terminated when LOGSYS_OK is returned.
 * @return LOGSYS_OK / LOGSYS_ERR_PARAM / LOGSYS_ERR_TRUNC.
 */
LogSysErr json_escape(char *dst, uint32_t cap, const char *src);

/* ------------------------------------------------------------------ */
/* Event lifecycle                                                     */
/* ------------------------------------------------------------------ */

LogSysErr evt_init(LogEvent *e, const char *msg, Severity sev, const char *src);
LogSysErr evt_add_tag(LogEvent *e, const char *k, const char *v);
LogSysErr evt_to_json(const LogEvent *e, char *buf, uint32_t cap);
LogSysErr evt_from_line(const char *line, const char *src, LogEvent *out);

#endif /* LOG_EVENT_H */
