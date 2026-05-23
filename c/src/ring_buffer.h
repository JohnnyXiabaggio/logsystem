#ifndef RING_BUFFER_H
#define RING_BUFFER_H

#include "log_event.h"
#include <pthread.h>
#include <stddef.h>
#include <stdint.h>

typedef struct {
    LogEvent        *buf;
    size_t           cap;
    size_t           head;
    size_t           tail;
    size_t           count;
    size_t           dropped;
    uint64_t         total_in;
    uint64_t         total_out;
    pthread_mutex_t  mu;
    pthread_cond_t   notempty;
} RingBuffer;

int    rb_init(RingBuffer *rb, size_t cap);
void   rb_destroy(RingBuffer *rb);

/* Returns 0 on success, -1 if buffer is full (event dropped). */
int    rb_push(RingBuffer *rb, const LogEvent *e);

/* Drains up to `max` events into `out`. Returns count drained. */
size_t rb_drain(RingBuffer *rb, LogEvent *out, size_t max);

void   rb_stats(const RingBuffer *rb,
                size_t *queued, uint64_t *total_in,
                uint64_t *total_out, size_t *dropped);

#endif /* RING_BUFFER_H */
