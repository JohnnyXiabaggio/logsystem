/**
 * @file ring_buffer.h
 * @brief Bounded MPMC event queue backed by a statically allocated pool.
 *
 * Compliance:
 *   - MISRA C:2012 Rule 21.3: no malloc/free — pool is file-scope static.
 *   - IEC 61508: deterministic memory; worst-case capacity = RB_CAPACITY.
 *   - All operations validate inputs and return LogSysErr.
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
    pthread_cond_t  notempty;
    bool_t          initialised;
} RingBuffer;

/**
 * Initialise the ring buffer.  Must be called exactly once before any
 * other operation.  The internal pool is statically allocated and
 * cannot be parameterised at runtime; pass cap == RB_CAPACITY.
 */
LogSysErr rb_init(RingBuffer *rb);

/** Destroy ring buffer resources (mutex + condvar). */
LogSysErr rb_destroy(RingBuffer *rb);

/**
 * Push an event.  Returns LOGSYS_ERR_FULL if the queue is at capacity;
 * the caller MUST observe this return code so dropped events are
 * counted (MISRA 17.7, IEC 61508 fault detection).
 */
LogSysErr rb_push(RingBuffer *rb, const LogEvent *e);

/**
 * Drain up to max events into the caller-supplied array.
 * @param[out] out_count  number of events actually drained.
 * @return LOGSYS_OK or LOGSYS_ERR_PARAM.
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
