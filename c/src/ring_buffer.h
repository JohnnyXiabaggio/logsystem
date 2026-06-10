/**
 * @file ring_buffer.h
 * @brief Bounded event queue backed by a statically allocated pool.
 *
 * Compliance:
 *   - MISRA C:2012 Rule 21.3: no malloc/free — pool is file-scope static.
 *   - IEC 61508: deterministic memory; worst-case capacity = RB_CAPACITY.
 *
 * Backpressure policy (issue events must survive incident storms):
 *   - Incoming event with severity >= ERROR and a full ring evicts the
 *     OLDEST queued event to make room (the newest high-severity event
 *     is the one the cloud most needs).
 *   - Incoming event below ERROR and a full ring is rejected
 *     (LOGSYS_ERR_FULL) — low-severity noise never displaces queued data.
 *
 * Wake policy (flush latency):
 *   - rb_push wakes a waiter (rb_wait_wake) when the pushed event has
 *     severity >= ERROR or occupancy reaches RB_WAKE_WATERMARK.
 *   - Routine traffic is batched: the flush thread's timed wait simply
 *     expires after its interval.
 *
 * The storage pool is a single static array: only ONE RingBuffer may be
 * initialised at a time; rb_init enforces this (LOGSYS_ERR_STATE).
 */

#ifndef RING_BUFFER_H
#define RING_BUFFER_H

#include "logsys_types.h"
#include "log_event.h"
#include <pthread.h>

typedef struct {
    LogEvent       *pool;       /* points to file-scope static array  */
    uint32_t        cap;        /* equals RB_CAPACITY at runtime      */
    uint32_t        head;
    uint32_t        tail;
    uint32_t        count;
    uint32_t        dropped;
    uint64_t        total_in;
    uint64_t        total_out;
    pthread_mutex_t mu;
    pthread_cond_t  wake;
    bool_t          wake_pending;
    bool_t          initialised;
} RingBuffer;

/** Initialise. Fails with LOGSYS_ERR_STATE if another instance owns the
 *  static pool. */
LogSysErr rb_init(RingBuffer *rb);

/** Destroy ring buffer resources and release the static pool. */
LogSysErr rb_destroy(RingBuffer *rb);

/**
 * Push an event (see backpressure policy above).
 * @return LOGSYS_OK        accepted (possibly evicting the oldest event)
 *         LOGSYS_ERR_FULL  rejected: ring full and severity < ERROR
 */
LogSysErr rb_push(RingBuffer *rb, const LogEvent *e);

/**
 * Block until an urgent wake arrives or timeout_ms elapses.
 * @return LOGSYS_OK          woken by rb_push (urgent / watermark)
 *         LOGSYS_ERR_TIMEOUT timed out (normal batching cadence)
 */
LogSysErr rb_wait_wake(RingBuffer *rb, uint32_t timeout_ms);

/** Wake a waiter immediately (e.g. to unblock shutdown). */
LogSysErr rb_wake(RingBuffer *rb);

/**
 * Drain up to max events into the caller-supplied array.
 * @param[out] out_count  number of events actually drained.
 */
LogSysErr rb_drain(RingBuffer *rb, LogEvent *out, uint32_t max,
                   uint32_t *out_count);

/** Atomic snapshot of stats.  Any output pointer may be NULL. */
LogSysErr rb_stats(RingBuffer *rb,
                   uint32_t *queued,
                   uint64_t *total_in,
                   uint64_t *total_out,
                   uint32_t *dropped);

#endif /* RING_BUFFER_H */
