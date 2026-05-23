#include "ring_buffer.h"
#include <stdlib.h>
#include <string.h>

int rb_init(RingBuffer *rb, size_t cap) {
    rb->buf = malloc(cap * sizeof(LogEvent));
    if (!rb->buf) return -1;
    rb->cap      = cap;
    rb->head     = 0;
    rb->tail     = 0;
    rb->count    = 0;
    rb->dropped  = 0;
    rb->total_in  = 0;
    rb->total_out = 0;
    pthread_mutex_init(&rb->mu, NULL);
    pthread_cond_init(&rb->notempty, NULL);
    return 0;
}

void rb_destroy(RingBuffer *rb) {
    free(rb->buf);
    rb->buf = NULL;
    pthread_mutex_destroy(&rb->mu);
    pthread_cond_destroy(&rb->notempty);
}

int rb_push(RingBuffer *rb, const LogEvent *e) {
    pthread_mutex_lock(&rb->mu);
    if (rb->count >= rb->cap) {
        rb->dropped++;
        pthread_mutex_unlock(&rb->mu);
        return -1;
    }
    rb->buf[rb->tail] = *e;
    rb->tail = (rb->tail + 1) % rb->cap;
    rb->count++;
    rb->total_in++;
    pthread_cond_signal(&rb->notempty);
    pthread_mutex_unlock(&rb->mu);
    return 0;
}

size_t rb_drain(RingBuffer *rb, LogEvent *out, size_t max) {
    pthread_mutex_lock(&rb->mu);
    size_t n = 0;
    while (n < max && rb->count > 0) {
        out[n++] = rb->buf[rb->head];
        rb->head = (rb->head + 1) % rb->cap;
        rb->count--;
        rb->total_out++;
    }
    pthread_mutex_unlock(&rb->mu);
    return n;
}

void rb_stats(const RingBuffer *rb,
              size_t *queued, uint64_t *total_in,
              uint64_t *total_out, size_t *dropped) {
    pthread_mutex_lock((pthread_mutex_t *)&rb->mu);
    if (queued)    *queued    = rb->count;
    if (total_in)  *total_in  = rb->total_in;
    if (total_out) *total_out = rb->total_out;
    if (dropped)   *dropped   = rb->dropped;
    pthread_mutex_unlock((pthread_mutex_t *)&rb->mu);
}
