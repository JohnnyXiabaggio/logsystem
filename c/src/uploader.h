/**
 * @file uploader.h
 * @brief Batch HTTP/1.1 POST uploader with exponential-backoff retry.
 *
 * Compliance:
 *   - No dynamic memory; batch JSON built in a file-scope static pool.
 *   - All return values checked (MISRA 17.7).
 *   - Integer port range validated (CWE-20).
 *   - API key never written to a log line (CWE-532).
 */

#ifndef UPLOADER_H
#define UPLOADER_H

#include "logsys_types.h"
#include "log_event.h"

#define UPLOADER_URL_MAX  (512U)
#define UPLOADER_KEY_MAX  (256U)

typedef struct {
    char     endpoint[UPLOADER_URL_MAX];
    char     api_key[UPLOADER_KEY_MAX];
    uint8_t  retry_attempts;     /* default 4 */
    uint32_t backoff_ms;         /* doubles each attempt */
    uint32_t timeout_sec;
    bool_t   dry_run;            /* TRUE = no network, log only       */
    bool_t   initialised;

    /* Read-only stats. */
    uint64_t total_batches;
    uint64_t total_sent;
    uint64_t total_failed;
} Uploader;

LogSysErr uploader_init(Uploader *u);

/**
 * Send a contiguous array of events.  Splits internally into chunks
 * of at most UPLOADER_BATCH_MAX.
 * @return LOGSYS_OK if every chunk delivered, LOGSYS_ERR_NET otherwise.
 */
LogSysErr uploader_send(Uploader *u, const LogEvent *events, uint32_t count);

#endif /* UPLOADER_H */
