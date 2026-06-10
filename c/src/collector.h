/**
 * @file collector.h
 * @brief File-tail event collector with static state.
 *
 * Events are delivered through an EventSink callback so the pipeline
 * can observe them (issue detection) at INGEST time, before queueing.
 *
 * The file-tail state array is a single static pool: only one
 * Collector may be started at a time (enforced in collector_start).
 */

#ifndef COLLECTOR_H
#define COLLECTOR_H

#include "logsys_types.h"
#include "log_event.h"
#include <pthread.h>
#include <stdio.h>      /* FILE * */

/** Sink invoked for every collected event (returns rb_push-style rc). */
typedef LogSysErr (*EventSink)(void *ctx, const LogEvent *e);

typedef struct {
    char    path[COLLECTOR_PATH_MAX];
    FILE   *fp;
    long    pos;
    long    last_size;
} FileTailState;

typedef struct {
    EventSink          sink;
    void              *sink_ctx;
    volatile bool_t    running;
    pthread_t          thread;
    bool_t             thread_started;

    char     paths[COLLECTOR_MAX_FILES][COLLECTOR_PATH_MAX];
    uint8_t  nfiles;
    uint32_t poll_ms;

    /* Diagnostic counters (read by the health reporter). */
    uint64_t lines_read;
    uint64_t lines_dropped;   /* sink returned LOGSYS_ERR_FULL */
    uint64_t lines_truncated; /* line exceeded EVT_MSG_MAX-1   */
} Collector;

LogSysErr collector_init(Collector *c, EventSink sink, void *sink_ctx,
                         uint32_t poll_ms);
LogSysErr collector_add_file(Collector *c, const char *path);
LogSysErr collector_start(Collector *c);
LogSysErr collector_stop(Collector *c);
LogSysErr collector_stats(Collector *c,
                          uint64_t *lines_read,
                          uint64_t *lines_dropped,
                          uint64_t *lines_truncated);

/**
 * Bounded line read: fills buf (cap >= 2) up to the newline or cap-1
 * bytes; if the line is longer, the remainder is consumed and
 * discarded so the next read starts at a true line boundary.
 * @param[out] truncated  set TRUE when the tail of the line was discarded.
 * @return LOGSYS_OK, LOGSYS_ERR_IO at EOF/no-data, LOGSYS_ERR_PARAM.
 */
LogSysErr collector_read_line(FILE *fp, char *buf, uint32_t cap,
                              bool_t *truncated);

#endif /* COLLECTOR_H */
