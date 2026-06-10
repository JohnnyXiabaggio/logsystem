/**
 * @file collector.c
 * @brief Per-collector polling thread that tails log files.
 *
 * - No heap; fixed paths array and a static file-state pool.
 * - Long lines are truncated at EVT_MSG_MAX-1 and the remainder is
 *   consumed, so one log line is always exactly one event (fragments
 *   are never re-classified with the wrong severity).
 * - Sink return values are captured into diagnostic counters.
 */

#include "collector.h"

#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <time.h>

/* Cap on lines drained from a single file per poll cycle.
 * Prevents starvation of other files (functional safety). */
#define COLLECTOR_LINES_PER_CYCLE  (1024U)

/* Bound on bytes discarded from one over-long line (1 MiB). */
#define COLLECTOR_DISCARD_MAX      (1048576U)

/* File-scope static pool — one slot per maximum-allowed file.
 * s_states_owner enforces the single-instance contract. */
static FileTailState     s_file_states[COLLECTOR_MAX_FILES];
static const Collector  *s_states_owner = NULL;

/* ------------------------------------------------------------------ */
/* Bounded line reader (shared with main.c stdin mode)                 */
/* ------------------------------------------------------------------ */

LogSysErr collector_read_line(FILE *fp, char *buf, uint32_t cap,
                              bool_t *truncated)
{
    LogSysErr rc = LOGSYS_OK;

    if ((fp == NULL) || (buf == NULL) || (cap < 2U) ||
        (truncated == NULL)) {
        rc = LOGSYS_ERR_PARAM;
    } else {
        *truncated = LOGSYS_FALSE;
        if (fgets(buf, (int)cap, fp) == NULL) {
            rc = LOGSYS_ERR_IO;     /* EOF or no data */
        } else {
            const size_t len = strlen(buf);
            if ((len == ((size_t)cap - 1U)) && (buf[len - 1U] != '\n')) {
                /* Line continues — consume the remainder so the next
                 * read starts at a real line boundary. Bounded. */
                uint32_t guard = COLLECTOR_DISCARD_MAX;
                int      ch    = 0;
                *truncated = LOGSYS_TRUE;
                do {
                    ch = fgetc(fp);
                    guard--;
                } while ((ch != EOF) && (ch != (int)'\n') && (guard > 0U));
            }
        }
    }
    return rc;
}

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

static void tail_poll(FileTailState *st, Collector *c)
{
    struct stat sb;

    if ((st == NULL) || (c == NULL)) {
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
                    bool_t truncated = LOGSYS_FALSE;
                    if (collector_read_line(st->fp, line, sizeof(line),
                                            &truncated) != LOGSYS_OK) {
                        keep_reading = LOGSYS_FALSE;
                    } else {
                        LogEvent  evt;
                        LogSysErr rc = evt_from_line(line, st->path, &evt);
                        if (rc == LOGSYS_OK) {
                            c->lines_read++;
                            if (truncated == LOGSYS_TRUE) {
                                c->lines_truncated++;
                                (void)evt_add_tag(&evt, "truncated", "1");
                            }
                            if (c->sink(c->sink_ctx, &evt) ==
                                LOGSYS_ERR_FULL) {
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

        for (i = 0U; i < c->nfiles; i++) {
            (void)memset(&s_file_states[i], 0, sizeof(s_file_states[i]));
            (void)snprintf(s_file_states[i].path,
                           sizeof(s_file_states[i].path),
                           "%s", c->paths[i]);
            tail_open(&s_file_states[i]);
        }

        while (c->running == LOGSYS_TRUE) {
            for (i = 0U; i < c->nfiles; i++) {
                tail_poll(&s_file_states[i], c);
            }

            {
                struct timespec ts;
                ts.tv_sec  = (time_t)(c->poll_ms / 1000U);
                ts.tv_nsec = (long)((c->poll_ms % 1000U) * 1000000U);
                /* nanosleep may return EINTR; we accept that. */
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

LogSysErr collector_init(Collector *c, EventSink sink, void *sink_ctx,
                         uint32_t poll_ms)
{
    LogSysErr rc = LOGSYS_OK;

    if ((c == NULL) || (sink == NULL)) {
        rc = LOGSYS_ERR_PARAM;
    } else {
        (void)memset(c, 0, sizeof(*c));
        c->sink           = sink;
        c->sink_ctx       = sink_ctx;
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
    } else if ((s_states_owner != NULL) && (s_states_owner != c)) {
        rc = LOGSYS_ERR_STATE;      /* static file-state pool in use */
    } else {
        s_states_owner = c;
        c->running     = LOGSYS_TRUE;
        if (pthread_create(&c->thread, NULL, collector_thread, c) != 0) {
            c->running     = LOGSYS_FALSE;
            s_states_owner = NULL;
            rc             = LOGSYS_ERR_SYS;
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
        if (s_states_owner == c) {
            s_states_owner = NULL;
        }
    }
    return rc;
}

LogSysErr collector_stats(Collector *c,
                          uint64_t *lines_read,
                          uint64_t *lines_dropped,
                          uint64_t *lines_truncated)
{
    LogSysErr rc = LOGSYS_OK;

    if (c == NULL) {
        rc = LOGSYS_ERR_PARAM;
    } else {
        /* Counters are written by one thread and read for diagnostics;
         * a torn read of a uint64 is acceptable for health output. */
        if (lines_read      != NULL) { *lines_read      = c->lines_read;      }
        if (lines_dropped   != NULL) { *lines_dropped   = c->lines_dropped;   }
        if (lines_truncated != NULL) { *lines_truncated = c->lines_truncated; }
    }
    return rc;
}
