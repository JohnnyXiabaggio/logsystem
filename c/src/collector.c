/**
 * @file collector.c
 * @brief Per-collector polling thread that tails log files.
 *
 * Compliance highlights:
 *   - No heap (strdup replaced by snprintf into fixed paths array).
 *   - pthread_create return value checked.
 *   - Discarded rb_push return value now captured into lines_dropped.
 *   - Bounded loops (max files, max lines per poll cycle).
 *   - File operations validated; rotation detection via stat().
 */

#include "collector.h"

#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <time.h>
#include <errno.h>

/* Cap on lines drained from a single file per poll cycle.
 * Prevents starvation of other files (functional safety). */
#define COLLECTOR_LINES_PER_CYCLE  (1024U)

/* File-scope static state — one slot per maximum-allowed file. */
static FileTailState s_file_states[COLLECTOR_MAX_FILES];

/* ------------------------------------------------------------------ */
/* Internal helpers — all static (MISRA 8.7).                         */
/* ------------------------------------------------------------------ */

static void tail_close(FileTailState *st)
{
    if ((st != NULL) && (st->fp != NULL)) {
        (void)fclose(st->fp);
        st->fp = NULL;
    }
}

static void tail_open(FileTailState *st)
{
    if (st != NULL) {
        tail_close(st);
        st->fp = fopen(st->path, "r");
        if (st->fp != NULL) {
            if (fseek(st->fp, 0L, SEEK_END) == 0) {
                long p = ftell(st->fp);
                if (p >= 0L) {
                    st->pos       = p;
                    st->last_size = p;
                } else {
                    tail_close(st);
                }
            } else {
                tail_close(st);
            }
        }
    }
}

static void tail_poll(FileTailState *st, RingBuffer *rb, Collector *c)
{
    struct stat sb;

    if ((st == NULL) || (rb == NULL) || (c == NULL)) {
        /* defensive — never expected at runtime */
    } else if (stat(st->path, &sb) != 0) {
        tail_close(st);
    } else {
        if (st->fp == NULL) {
            tail_open(st);
        } else if ((long)sb.st_size < st->last_size) {
            /* Truncation/rotation. */
            tail_open(st);
        } else {
            st->last_size = (long)sb.st_size;
        }

        if (st->fp != NULL) {
            if (fseek(st->fp, st->pos, SEEK_SET) == 0) {
                char     line[EVT_MSG_MAX];
                uint32_t lines_this_cycle = 0U;
                bool_t   keep_reading     = LOGSYS_TRUE;
                while ((keep_reading == LOGSYS_TRUE) &&
                       (lines_this_cycle < COLLECTOR_LINES_PER_CYCLE)) {
                    if (fgets(line, (int)sizeof(line), st->fp) == NULL) {
                        keep_reading = LOGSYS_FALSE;
                    } else {
                        LogEvent  evt;
                        LogSysErr rc = evt_from_line(line, st->path, &evt);
                        if (rc == LOGSYS_OK) {
                            c->lines_read++;
                            if (rb_push(rb, &evt) == LOGSYS_ERR_FULL) {
                                c->lines_dropped++;
                            }
                        }
                        lines_this_cycle++;
                    }
                }
                {
                    long p = ftell(st->fp);
                    if (p >= 0L) {
                        st->pos = p;
                    }
                }
            }
        }
    }
}

/* ------------------------------------------------------------------ */
/* Worker thread                                                       */
/* ------------------------------------------------------------------ */

static void *collector_thread(void *arg)
{
    if (arg != NULL) {
        Collector *c = (Collector *)arg;
        uint8_t    i;

        /* Initialise per-file state from collector configuration. */
        for (i = 0U; i < c->nfiles; i++) {
            (void)memset(&s_file_states[i], 0, sizeof(s_file_states[i]));
            (void)snprintf(s_file_states[i].path,
                           sizeof(s_file_states[i].path),
                           "%s", c->paths[i]);
            s_file_states[i].active = LOGSYS_TRUE;
            tail_open(&s_file_states[i]);
        }

        while (c->running == LOGSYS_TRUE) {
            for (i = 0U; i < c->nfiles; i++) {
                tail_poll(&s_file_states[i], c->rb, c);
            }

            {
                struct timespec ts;
                ts.tv_sec  = (time_t)(c->poll_ms / 1000U);
                ts.tv_nsec = (long)((c->poll_ms % 1000U) * 1000000U);
                /* nanosleep is allowed to return EINTR; we accept that. */
                (void)nanosleep(&ts, NULL);
            }
        }

        for (i = 0U; i < c->nfiles; i++) {
            tail_close(&s_file_states[i]);
        }
    }
    return NULL;
}

/* ------------------------------------------------------------------ */
/* Public API                                                          */
/* ------------------------------------------------------------------ */

LogSysErr collector_init(Collector *c, RingBuffer *rb, uint32_t poll_ms)
{
    LogSysErr rc = LOGSYS_OK;

    if ((c == NULL) || (rb == NULL)) {
        rc = LOGSYS_ERR_PARAM;
    } else {
        (void)memset(c, 0, sizeof(*c));
        c->rb             = rb;
        c->poll_ms        = (poll_ms == 0U) ? 1000U : poll_ms;
        c->running        = LOGSYS_FALSE;
        c->thread_started = LOGSYS_FALSE;
        c->nfiles         = 0U;
    }
    return rc;
}

LogSysErr collector_add_file(Collector *c, const char *path)
{
    LogSysErr rc = LOGSYS_OK;

    if ((c == NULL) || (path == NULL)) {
        rc = LOGSYS_ERR_PARAM;
    } else if (c->nfiles >= (uint8_t)COLLECTOR_MAX_FILES) {
        rc = LOGSYS_ERR_FULL;
    } else {
        const size_t len = strlen(path);
        if ((len == 0U) || (len >= COLLECTOR_PATH_MAX)) {
            rc = LOGSYS_ERR_PARAM;
        } else {
            int n = snprintf(c->paths[c->nfiles], COLLECTOR_PATH_MAX,
                             "%s", path);
            if ((n < 0) || ((size_t)n >= COLLECTOR_PATH_MAX)) {
                rc = LOGSYS_ERR_TRUNC;
            } else {
                c->nfiles = (uint8_t)(c->nfiles + 1U);
            }
        }
    }
    return rc;
}

LogSysErr collector_start(Collector *c)
{
    LogSysErr rc = LOGSYS_OK;

    if (c == NULL) {
        rc = LOGSYS_ERR_PARAM;
    } else if (c->thread_started == LOGSYS_TRUE) {
        rc = LOGSYS_ERR_STATE;
    } else {
        c->running = LOGSYS_TRUE;
        if (pthread_create(&c->thread, NULL, collector_thread, c) != 0) {
            c->running = LOGSYS_FALSE;
            rc         = LOGSYS_ERR_SYS;
        } else {
            c->thread_started = LOGSYS_TRUE;
        }
    }
    return rc;
}

LogSysErr collector_stop(Collector *c)
{
    LogSysErr rc = LOGSYS_OK;

    if (c == NULL) {
        rc = LOGSYS_ERR_PARAM;
    } else if (c->thread_started == LOGSYS_FALSE) {
        rc = LOGSYS_ERR_STATE;
    } else {
        c->running = LOGSYS_FALSE;
        if (pthread_join(c->thread, NULL) != 0) {
            rc = LOGSYS_ERR_SYS;
        }
        c->thread_started = LOGSYS_FALSE;
    }
    return rc;
}
