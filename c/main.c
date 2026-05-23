/*
 * logsystem — real-time log collection, cloud upload, and issue monitoring.
 *
 * Usage:
 *   logsystem [OPTIONS]
 *
 * Options:
 *   -w PATH        Watch a log file (repeatable, up to 16 files)
 *   -e URL         Cloud ingest endpoint (or set LOGSYS_ENDPOINT)
 *   -k KEY         API key / bearer token (or set LOGSYS_API_KEY)
 *   -A URL         Alert webhook endpoint (or set LOGSYS_ALERT_ENDPOINT)
 *   -n             Dry-run: log batches locally, no network calls
 *   -s             Read events from stdin (one per line)
 *   -i SEC         Flush interval in seconds (default 5)
 *   -h             Show help
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <inttypes.h>

#include "src/pipeline.h"
#include "src/log_event.h"

static void usage(const char *prog) {
    fprintf(stderr,
        "Usage: %s [OPTIONS]\n"
        "  -w PATH   tail a log file (up to 16, repeatable)\n"
        "  -e URL    cloud ingest endpoint\n"
        "  -k KEY    API bearer token\n"
        "  -A URL    alert webhook URL\n"
        "  -n        dry-run (no network)\n"
        "  -s        also read from stdin\n"
        "  -i SEC    flush interval seconds (default 5)\n"
        "  -h        show this help\n"
        "\n"
        "Env vars: LOGSYS_ENDPOINT, LOGSYS_API_KEY,\n"
        "          LOGSYS_ALERT_ENDPOINT, LOGSYS_DRY_RUN=1\n",
        prog);
}

int main(int argc, char **argv) {
    Pipeline p;
    if (pipeline_init(&p) < 0) {
        fprintf(stderr, "pipeline_init failed\n");
        return 1;
    }

    /* Defaults from environment */
    const char *env_ep  = getenv("LOGSYS_ENDPOINT");
    const char *env_key = getenv("LOGSYS_API_KEY");
    const char *env_ale = getenv("LOGSYS_ALERT_ENDPOINT");
    const char *env_dry = getenv("LOGSYS_DRY_RUN");

    if (env_ep)  snprintf(p.uploader.endpoint, UPLOADER_URL_MAX, "%s", env_ep);
    if (env_key) snprintf(p.uploader.api_key,  UPLOADER_KEY_MAX, "%s", env_key);
    if (env_ale) snprintf(p.monitor.alert_endpoint, UPLOADER_URL_MAX, "%s", env_ale);
    if (env_dry && (env_dry[0] == '1' || env_dry[0] == 't' || env_dry[0] == 'y'))
        p.uploader.dry_run = 1;

    int stdin_mode = 0;
    int opt;
    while ((opt = getopt(argc, argv, "w:e:k:A:nsi:h")) != -1) {
        switch (opt) {
            case 'w':
                if (collector_add_file(&p.collector, optarg) < 0)
                    fprintf(stderr, "warning: too many watch paths\n");
                break;
            case 'e':
                snprintf(p.uploader.endpoint, UPLOADER_URL_MAX, "%s", optarg);
                break;
            case 'k':
                snprintf(p.uploader.api_key, UPLOADER_KEY_MAX, "%s", optarg);
                break;
            case 'A':
                snprintf(p.monitor.alert_endpoint, UPLOADER_URL_MAX, "%s", optarg);
                break;
            case 'n':
                p.uploader.dry_run = 1;
                break;
            case 's':
                stdin_mode = 1;
                break;
            case 'i':
                p.flush_interval_sec = atof(optarg);
                break;
            case 'h':
                usage(argv[0]);
                return 0;
            default:
                usage(argv[0]);
                return 1;
        }
    }

    pipeline_start(&p);

    if (stdin_mode) {
        /* Read events from stdin in the main thread */
        char line[EVT_MSG_MAX];
        while (fgets(line, sizeof(line), stdin)) {
            LogEvent evt;
            if (evt_from_line(line, "stdin", &evt) == 0)
                rb_push(&p.rb, &evt);
        }
        /* stdin closed — wait for flush then exit */
    } else {
        pipeline_run_until_signal(&p);
    }

    pipeline_stop(&p);
    pipeline_free(&p);
    return 0;
}
