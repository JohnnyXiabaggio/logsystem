/**
 * @file ring_buffer.c
 * @brief Static-pool ring buffer with severity-aware backpressure and
 *        urgent-wake support.
 *
 * - No dynamic allocation (MISRA 21.3, IEC 61508).
 * - All pthread return values checked (MISRA 17.7, CWE-252).
 * - Condvar uses CLOCK_MONOTONIC so wall-clock steps cannot distort the
 *   flush cadence.
 */

#include "ring_buffer.h"
#include <string.h>
#include <errno.h>
#include <time.h>

/* ------------------------------------------------------------------ */
/* Static pool — the sole source of LogEvent storage for the queue.   */
/* s_pool_owner enforces the single-instance contract the static pool */
/* imposes (the API would otherwise silently alias two "instances").  */
/* ------------------------------------------------------------------ */
static LogEvent     s_rb_pool[RB_CAPACITY];
static RingBuffer  *s_pool_owner = NULL;

/* ------------------------------------------------------------------ */
/* Init / destroy                                                      */
/* ------------------------------------------------------------------ */

LogSysErr rb_init(RingBuffer *rb)
{
    LogSysErr rc = LOGSYS_OK;

    if (rb == NULL) {
        rc = LOGSYS_ERR_PARAM;
    } else if (s_pool_owner != NULL) {
        rc = LOGSYS_ERR_STATE;      /* pool already owned */
    } else {
        pthread_condattr_t ca;

        (void)memset(rb, 0, sizeof(*rb));
        rb->pool         = s_rb_pool;
        rb->cap          = RB_CAPACITY;
        rb->wake_pending = LOGSYS_FALSE;
        rb->initialised  = LOGSYS_FALSE;

        if (pthread_mutex_init(&rb->mu, NULL) != 0) {
            rc = LOGSYS_ERR_SYS;
        } else if (pthread_condattr_init(&ca) != 0) {
            (void)pthread_mutex_destroy(&rb->mu);
            rc = LOGSYS_ERR_SYS;
        } else {
            if (pthread_condattr_setclock(&ca, CLOCK_MONOTONIC) != 0) {
                rc = LOGSYS_ERR_SYS;
            } else if (pthread_cond_init(&rb->wake, &ca) != 0) {
                rc = LOGSYS_ERR_SYS;
            } else {
                rb->initialised = LOGSYS_TRUE;
                s_pool_owner    = rb;
            }
            (void)pthread_condattr_destroy(&ca);
            if (rb->initialised == LOGSYS_FALSE) {
                (void)pthread_mutex_destroy(&rb->mu);
            }
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
        (void)pthread_cond_destroy(&rb->wake);
        (void)pthread_mutex_destroy(&rb->mu);
        rb->initialised = LOGSYS_FALSE;
        rb->pool        = NULL;
        if (s_pool_owner == rb) {
            s_pool_owner = NULL;
        }
    }
    return rc;
}

/* ------------------------------------------------------------------ */
/* Push — severity-aware backpressure + urgent wake                    */
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
        bool_t do_wake = LOGSYS_FALSE;

        if (rb->count >= rb->cap) {
            if (e->severity >= SEV_ERROR) {
                /* Evict the oldest queued event so the newest issue
                 * event survives the storm.  The evicted event counts
                 * as dropped. */
                rb->head = (rb->head + 1U) % rb->cap;
                rb->count--;
                rb->dropped++;
            } else {
                rb->dropped++;
                rc = LOGSYS_ERR_FULL;
            }
        }

        if (rc == LOGSYS_OK) {
            rb->pool[rb->tail] = *e;
            rb->tail           = (rb->tail + 1U) % rb->cap;
            rb->count++;
            rb->total_in++;

            if ((e->severity >= SEV_ERROR) ||
                (rb->count >= RB_WAKE_WATERMARK)) {
                do_wake = LOGSYS_TRUE;
            }
        }

        if ((do_wake == LOGSYS_TRUE) &&
            (rb->wake_pending == LOGSYS_FALSE)) {
            rb->wake_pending = LOGSYS_TRUE;
            /* Signal failure is recoverable: the timed wait expires. */
            (void)pthread_cond_signal(&rb->wake);
        }
        (void)pthread_mutex_unlock(&rb->mu);
    }
    return rc;
}

LogSysErr rb_wake(RingBuffer *rb)
{
    LogSysErr rc = LOGSYS_OK;

    if (rb == NULL) {
        rc = LOGSYS_ERR_PARAM;
    } else if (rb->initialised == LOGSYS_FALSE) {
        rc = LOGSYS_ERR_STATE;
    } else if (pthread_mutex_lock(&rb->mu) != 0) {
        rc = LOGSYS_ERR_SYS;
    } else {
        rb->wake_pending = LOGSYS_TRUE;
        (void)pthread_cond_signal(&rb->wake);
        (void)pthread_mutex_unlock(&rb->mu);
    }
    return rc;
}

/* ------------------------------------------------------------------ */
/* Wait for an urgent wake (or timeout = normal batching cadence)     */
/* ------------------------------------------------------------------ */

LogSysErr rb_wait_wake(RingBuffer *rb, uint32_t timeout_ms)
{
    LogSysErr rc = LOGSYS_OK;

    if (rb == NULL) {
        rc = LOGSYS_ERR_PARAM;
    } else if (rb->initialised == LOGSYS_FALSE) {
        rc = LOGSYS_ERR_STATE;
    } else if (pthread_mutex_lock(&rb->mu) != 0) {
        rc = LOGSYS_ERR_SYS;
    } else {
        struct timespec deadline;

        (void)clock_gettime(CLOCK_MONOTONIC, &deadline);
        deadline.tv_sec  += (time_t)(timeout_ms / 1000U);
        deadline.tv_nsec += (long)((timeout_ms % 1000U) * 1000000U);
        if (deadline.tv_nsec >= 1000000000L) {
            deadline.tv_sec  += 1;
            deadline.tv_nsec -= 1000000000L;
        }

        {
            int    wrc     = 0;
            bool_t expired = LOGSYS_FALSE;
            /* Bounded by the deadline; loop absorbs spurious wakeups. */
            while ((rb->wake_pending == LOGSYS_FALSE) &&
                   (expired == LOGSYS_FALSE)) {
                wrc = pthread_cond_timedwait(&rb->wake, &rb->mu, &deadline);
                if (wrc == ETIMEDOUT) {
                    expired = LOGSYS_TRUE;
                } else if (wrc != 0) {
                    expired = LOGSYS_TRUE;   /* treat as timeout */
                } else {
                    /* signalled or spurious — loop re-checks predicate */
                }
            }
        }

        if (rb->wake_pending == LOGSYS_TRUE) {
            rb->wake_pending = LOGSYS_FALSE;
            rc = LOGSYS_OK;
        } else {
            rc = LOGSYS_ERR_TIMEOUT;
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
