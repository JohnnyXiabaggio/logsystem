/**
 * @file logsys_types.h
 * @brief Common types, error codes, and compile-time invariants.
 *
 * Compliance:
 *   - MISRA C:2012 (mandatory + required + many advisory rules)
 *   - IEC 61508 SIL-2 (no dynamic allocation, deterministic resource use)
 *   - CWE Top-25 mitigations (bounds, integer overflow, unchecked returns)
 *
 * All translation units include this header to obtain:
 *   - fixed-width integer types
 *   - the project-wide bool_t alias
 *   - the LogSysErr error-code enumeration
 *   - compile-time capacity constants and static assertions
 */

#ifndef LOGSYS_TYPES_H
#define LOGSYS_TYPES_H

#include <stdint.h>   /* MISRA 21.4-compliant: fixed-width types */
#include <stddef.h>   /* size_t, NULL */

/* ------------------------------------------------------------------ */
/* Boolean type                                                        */
/*                                                                     */
/* MISRA C:2012 Rule 14.4 requires controlling expressions of         */
/* "essentially Boolean" type.  We avoid <stdbool.h> (deviation        */
/* permitted) to keep an 8-bit storage class for portability with     */
/* embedded targets that lack C99 _Bool support.                       */
/* ------------------------------------------------------------------ */
typedef uint8_t bool_t;

#define LOGSYS_TRUE   ((bool_t)1U)
#define LOGSYS_FALSE  ((bool_t)0U)

/* ------------------------------------------------------------------ */
/* Error codes                                                         */
/*                                                                     */
/* All API functions that can fail return LogSysErr.  Zero is the     */
/* only success value; all negatives are distinct failure modes.       */
/* ------------------------------------------------------------------ */
typedef int32_t LogSysErr;

#define LOGSYS_OK            ( 0)   /**< Success */
#define LOGSYS_ERR_PARAM     (-1)   /**< NULL pointer or out-of-range value */
#define LOGSYS_ERR_FULL      (-2)   /**< Pool/buffer capacity exhausted */
#define LOGSYS_ERR_IO        (-3)   /**< I/O failure */
#define LOGSYS_ERR_NET       (-4)   /**< Network failure */
#define LOGSYS_ERR_TRUNC     (-5)   /**< Output truncated — bounds enforced */
#define LOGSYS_ERR_TIMEOUT   (-6)   /**< Operation timed out */
#define LOGSYS_ERR_STATE     (-7)   /**< Invalid state for this call */
#define LOGSYS_ERR_OVERFLOW  (-8)   /**< Integer arithmetic would overflow */
#define LOGSYS_ERR_SYS       (-9)   /**< OS service failure (pthread, etc.) */

/* ------------------------------------------------------------------ */
/* Compile-time capacity constants                                     */
/*                                                                     */
/* All buffer sizes are fixed at compile time so the static analyser  */
/* can prove worst-case memory usage (IEC 61508 §7.4.4.7).             */
/* Override at build time via -D if a different point in the design   */
/* envelope is required.                                               */
/* ------------------------------------------------------------------ */

#ifndef RB_CAPACITY
#  define RB_CAPACITY          (1000U)
#endif

#ifndef COLLECTOR_MAX_FILES
#  define COLLECTOR_MAX_FILES  (16U)
#endif

#ifndef COLLECTOR_PATH_MAX
#  define COLLECTOR_PATH_MAX   (256U)
#endif

#ifndef UPLOADER_BATCH_MAX
#  define UPLOADER_BATCH_MAX   (200U)
#endif

#ifndef MON_WIN_MAX
#  define MON_WIN_MAX          (512U)
#endif

#ifndef HTTP_TIMEOUT_SEC
#  define HTTP_TIMEOUT_SEC     (10)
#endif

/* TCP port valid range — used to validate parsed URLs (CWE-20). */
#define LOGSYS_PORT_MIN        (1)
#define LOGSYS_PORT_MAX        (65535)

/* ------------------------------------------------------------------ */
/* Compile-time assertions                                             */
/*                                                                     */
/* Implemented as an array-typedef trick to work on pre-C11 compilers */
/* and to satisfy MISRA Rule 1.1 (ISO/IEC 9899:1990 portability).      */
/* A failed assertion produces a negative-size-array diagnostic.       */
/* ------------------------------------------------------------------ */
#define LOGSYS_STATIC_ASSERT(cond, tag) \
    typedef char logsys_sa_##tag[(cond) ? 1 : -1]

LOGSYS_STATIC_ASSERT(RB_CAPACITY         > 0U,     rb_cap_pos);
LOGSYS_STATIC_ASSERT(COLLECTOR_MAX_FILES > 0U,     col_max_pos);
LOGSYS_STATIC_ASSERT(UPLOADER_BATCH_MAX  > 0U,     up_batch_pos);
LOGSYS_STATIC_ASSERT(MON_WIN_MAX         > 0U,     mon_win_pos);
LOGSYS_STATIC_ASSERT(COLLECTOR_PATH_MAX  >= 16U,   col_path_min);

/* Guard against absurd configuration that would exhaust .bss */
LOGSYS_STATIC_ASSERT(RB_CAPACITY        <= 100000U, rb_cap_sanity);
LOGSYS_STATIC_ASSERT(UPLOADER_BATCH_MAX <= 10000U,  up_batch_sanity);

/* ------------------------------------------------------------------ */
/* Helper macros                                                       */
/* ------------------------------------------------------------------ */

/* Silence "unused parameter" diagnostics in a MISRA-compliant way    */
/* (Rule 2.7 — unused parameters should be removed; where the         */
/* signature is fixed by an interface contract, mark it explicitly).  */
#define LOGSYS_UNUSED(x)  ((void)(x))

/* Array length for sized arrays — protects against pointer decay.    */
#define LOGSYS_ARRAY_LEN(a)  (sizeof(a) / sizeof((a)[0]))

#endif /* LOGSYS_TYPES_H */
