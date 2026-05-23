#ifndef LOG_EVENT_H
#define LOG_EVENT_H

#include <time.h>
#include <stddef.h>

#define EVT_MSG_MAX   1024
#define EVT_SRC_MAX   256
#define EVT_ID_LEN    37        /* "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx\0" */
#define EVT_TAGS_MAX  8
#define TAG_KEY_MAX   64
#define TAG_VAL_MAX   128
#define EVT_JSON_MAX  (EVT_MSG_MAX * 2 + 512)

typedef enum {
    SEV_DEBUG    = 10,
    SEV_INFO     = 20,
    SEV_WARNING  = 30,
    SEV_ERROR    = 40,
    SEV_CRITICAL = 50
} Severity;

typedef struct {
    char k[TAG_KEY_MAX];
    char v[TAG_VAL_MAX];
} Tag;

typedef struct {
    char        id[EVT_ID_LEN];
    struct timespec ts;
    Severity    severity;
    char        source[EVT_SRC_MAX];
    char        message[EVT_MSG_MAX];
    Tag         tags[EVT_TAGS_MAX];
    int         ntags;
} LogEvent;

/* ---- utilities shared across modules ---- */
const char *sev_label(Severity s);
Severity    sev_detect(const char *line);
void        uuid_gen(char out[EVT_ID_LEN]);
void        ts_iso8601(const struct timespec *ts, char *buf, size_t cap);
int         json_escape(char *dst, size_t cap, const char *src);

/* ---- event lifecycle ---- */
void evt_init(LogEvent *e, const char *msg, Severity sev, const char *src);
void evt_add_tag(LogEvent *e, const char *k, const char *v);
int  evt_to_json(const LogEvent *e, char *buf, size_t cap);
int  evt_from_line(const char *line, const char *src, LogEvent *out);

#endif /* LOG_EVENT_H */
