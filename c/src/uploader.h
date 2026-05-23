#ifndef UPLOADER_H
#define UPLOADER_H

#include "log_event.h"
#include <stddef.h>
#include <stdint.h>

#define UPLOADER_URL_MAX   512
#define UPLOADER_KEY_MAX   256
#define UPLOADER_BATCH_MAX 500

typedef struct {
    char     endpoint[UPLOADER_URL_MAX];
    char     api_key[UPLOADER_KEY_MAX];
    int      retry_attempts;    /* default 4 */
    double   backoff_sec;       /* doubles each attempt */
    double   timeout_sec;
    int      dry_run;           /* 1 = log locally, no network */

    /* stats (updated under no lock — read only for reporting) */
    uint64_t total_batches;
    uint64_t total_sent;
    uint64_t total_failed;
} Uploader;

void uploader_init(Uploader *u);

/* Send a batch of events; handles retry internally.
   Returns 0 if all events delivered, -1 if permanently failed. */
int  uploader_send(Uploader *u, const LogEvent *events, size_t count);

#endif /* UPLOADER_H */
