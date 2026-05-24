/**
 * @file collector.h
 * @brief File-tail event collector with static state.
 *
 * Compliance:
 *   - No dynamic memory (paths and file states are statically sized).
 *   - All return values checked (MISRA 17.7).
 *   - bool_t for run flag (MISRA 14.4).
 */

#ifndef COLLECTOR_H
#define COLLECTOR_H

#include "logsys_types.h"
#include "ring_buffer.h"
#include <pthread.h>
#include <stdio.h>      /* FILE * */

typedef struct {
    char    path[COLLECTOR_PATH_MAX];
    FILE   *fp;
    long    pos;
    long    last_size;
    bool_t  active;
} FileTailState;

typedef struct {
    RingBuffer        *rb;
    volatile bool_t    running;
    pthread_t          thread;
    bool_t             thread_started;

    char     paths[COLLECTOR_MAX_FILES][COLLECTOR_PATH_MAX];
    uint8_t  nfiles;
    uint32_t poll_ms;

    /* Diagnostic counters */
    uint64_t lines_read;
    uint64_t lines_dropped;   /* rb_push returned FULL */
} Collector;

LogSysErr collector_init(Collector *c, RingBuffer *rb, uint32_t poll_ms);
LogSysErr collector_add_file(Collector *c, const char *path);
LogSysErr collector_start(Collector *c);
LogSysErr collector_stop(Collector *c);

#endif /* COLLECTOR_H */
