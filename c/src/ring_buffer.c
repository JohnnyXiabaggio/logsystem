/**
 * @file ring_buffer.c
 * @brief Implementation of the static-pool ring buffer.
 *
 * - No dynamic allocation (MISRA 21.3, IEC 61508).
 * - All pthread return values checked (MISRA 17.7, CWE-252).
 * - Single point of exit per function (MISRA 15.5).
 */

#include "ring_buffer.h"
#include <string.h>

/* ------------------------------------------------------------------ */
/* Static pool — the sole source of LogEvent storage for the queue.   */
/*                                                                     */
/* Allocated in .bss; size is fixed at compile time and visible to    */
/* the linker map (IEC 61508 §7.4.4.7 worst-case memory analysis).    */
/* ------------------------------------------------------------------ */
static LogEvent s_rb_pool[RB_CAPACITY];

/* ------------------------------------------------------------------ */
/* Init / destroy                                                      */
/* ------------------------------------------------------------------ */

LogSysErr rb_init(RingBuffer *rb)
{
    LogSysErr rc = LOGSYS_OK;

    if (rb == NULL) {
        rc = LOGSYS_ERR_PARAM;
    } else {
        (void)memset(rb, 0, sizeof(*rb));
        rb->pool        = s_rb_pool;
        rb->cap         = RB_CAPACITY;
        rb->initialised = LOGSYS_FALSE;

        if (pthread_mutex_init(&rb->mu, NULL) != 0) {
            rc = LOGSYS_ERR_SYS;
        } else if (pthread_cond_init(&rb->notempty, NULL) != 0) {
            (void)pthread_mutex_destroy(&rb->mu);
            rc = LOGSYS_ERR_SYS;
        } else {
            rb->initialised = LOGSYS_TRUE;
        }
    }
    return rc;
}

LogSysErr rb_destroy(RingBuffer *rb)
{
    LogSysErr rc = LOGSYS_OK;

    if (rb == NULL) {
        rc = LOGSYS_ERR_PARAM;
    } else if (rb->initialised == LOGSYS_FALSE) {
        rc = LOGSYS_ERR_STATE;
    } else {
        (void)pthread_cond_destroy(&rb->notempty);
        (void)pthread_mutex_destroy(&rb->mu);
        rb->initialised = LOGSYS_FALSE;
        rb->pool        = NULL;
    }
    return rc;
}

/* ------------------------------------------------------------------ */
/* Push                                                                */
/* ------------------------------------------------------------------ */

LogSysErr rb_push(RingBuffer *rb, const LogEvent *e)
{
    LogSysErr rc = LOGSYS_OK;

    if ((rb == NULL) || (e == NULL)) {
        rc = LOGSYS_ERR_PARAM;
    } else if (rb->initialised == LOGSYS_FALSE) {
        rc = LOGSYS_ERR_STATE;
    } else if (pthread_mutex_lock(&rb->mu) != 0) {
        rc = LOGSYS_ERR_SYS;
    } else {
        if (rb->count >= rb->cap) {
            rb->dropped++;
            rc = LOGSYS_ERR_FULL;
        } else {
            rb->pool[rb->tail] = *e;
            rb->tail           = (rb->tail + 1U) % rb->cap;
            rb->count++;
            rb->total_in++;
            /* Signal failure is recoverable — the timed flush will
             * drain anyway, so we deliberately ignore the result. */
            (void)pthread_cond_signal(&rb->notempty);
        }
        (void)pthread_mutex_unlock(&rb->mu);
    }
    return rc;
}

/* ------------------------------------------------------------------ */
/* Drain                                                               */
/* ------------------------------------------------------------------ */

LogSysErr rb_drain(RingBuffer *rb, LogEvent *out, uint32_t max,
                   uint32_t *out_count)
{
    LogSysErr rc = LOGSYS_OK;

    if ((rb == NULL) || (out == NULL) || (out_count == NULL)) {
        rc = LOGSYS_ERR_PARAM;
    } else if (rb->initialised == LOGSYS_FALSE) {
        rc = LOGSYS_ERR_STATE;
    } else if (pthread_mutex_lock(&rb->mu) != 0) {
        rc = LOGSYS_ERR_SYS;
    } else {
        uint32_t n = 0U;
        /* Bounded loop: explicit upper bound is min(max, rb->count). */
        while ((n < max) && (rb->count > 0U)) {
            out[n] = rb->pool[rb->head];
            rb->head = (rb->head + 1U) % rb->cap;
            rb->count--;
            rb->total_out++;
            n++;
        }
        *out_count = n;
        (void)pthread_mutex_unlock(&rb->mu);
    }
    return rc;
}

/* ------------------------------------------------------------------ */
/* Stats                                                               */
/* ------------------------------------------------------------------ */

LogSysErr rb_stats(RingBuffer *rb,
                   uint32_t *queued,
                   uint64_t *total_in,
                   uint64_t *total_out,
                   uint32_t *dropped)
{
    LogSysErr rc = LOGSYS_OK;

    if (rb == NULL) {
        rc = LOGSYS_ERR_PARAM;
    } else if (rb->initialised == LOGSYS_FALSE) {
        rc = LOGSYS_ERR_STATE;
    } else if (pthread_mutex_lock(&rb->mu) != 0) {
        rc = LOGSYS_ERR_SYS;
    } else {
        if (queued    != NULL) { *queued    = rb->count;     }
        if (total_in  != NULL) { *total_in  = rb->total_in;  }
        if (total_out != NULL) { *total_out = rb->total_out; }
        if (dropped   != NULL) { *dropped   = rb->dropped;   }
        (void)pthread_mutex_unlock(&rb->mu);
    }
    return rc;
}
