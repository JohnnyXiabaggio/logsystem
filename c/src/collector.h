#ifndef COLLECTOR_H
#define COLLECTOR_H

#include "ring_buffer.h"
#include <pthread.h>
#include <stdio.h>

#define COLLECTOR_MAX_FILES 16

/* Per-file tail state */
typedef struct {
    char   path[512];
    FILE  *fp;
    long   pos;
    long   last_size;
} FileTailState;

typedef struct {
    RingBuffer      *rb;
    volatile int     running;
    pthread_t        thread;

    char            *paths[COLLECTOR_MAX_FILES];
    int              nfiles;
    int              poll_ms;
} Collector;

int  collector_init(Collector *c, RingBuffer *rb, int poll_ms);
int  collector_add_file(Collector *c, const char *path);
void collector_start(Collector *c);
void collector_stop(Collector *c);
void collector_free(Collector *c);

/* Inject a single event directly (useful from main thread / SDK). */
void collector_emit(Collector *c, const char *msg, Severity sev, const char *src);

#endif /* COLLECTOR_H */
