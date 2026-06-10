/**
 * @file main.c
 * @brief logsystem command-line driver.
 *
 * Cybersecurity:
 *   - strtol/strtod (not atoi/atof) with range checks (MISRA 21.7).
 *   - If -k is used, the argv slot is overwritten with '*' so the key
 *     does not appear in /proc/<pid>/cmdline (CWE-200 mitigation).
 *     The recommended deployment path is the LOGSYS_API_KEY env var.
 *   - All API return values checked.
 */

#include "src/logsys_types.h"
#include "src/pipeline.h"
#include "src/log_event.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

static void usage(const char *prog)
{
    (void)fprintf(stderr,
        "Usage: %s [OPTIONS]\n"
        "  -w PATH   tail a log file (up to %u, repeatable)\n"
        "  -e URL    cloud ingest endpoint (http:// or https://*)\n"
        "  -k KEY    API bearer token (PREFER env LOGSYS_API_KEY)\n"
        "  -A URL    alert webhook URL (http:// only)\n"
        "  -n        dry-run (no network)\n"
        "  -s        also read events from stdin\n"
        "  -i SEC    flush interval seconds (default 5, range 1..600)\n"
        "  -h        show this help\n"
        "\n"
        "Env vars (preferred for secrets):\n"
        "  LOGSYS_ENDPOINT, LOGSYS_API_KEY,\n"
        "  LOGSYS_ALERT_ENDPOINT, LOGSYS_DRY_RUN=1\n"
        "\n"
        "* https:// requires building with USE_CURL=1\n",
        prog, (unsigned)COLLECTOR_MAX_FILES);
}

/* Wipe a sensitive argv slot so it does not appear in /proc/.../cmdline. */
static void scrub_arg(char *s)
{
    if (s != NULL) {
        size_t i;
        const size_t len = strlen(s);
        for (i = 0U; i < len; i++) {
            s[i] = '*';
        }
    }
}

/* Validated integer parser: returns LOGSYS_OK if range-conformant. */
static LogSysErr parse_double_range(const char *s, double lo, double hi,
                                     double *out)
{
    LogSysErr rc   = LOGSYS_OK;
    char     *endp = NULL;
    double    v;

    if ((s == NULL) || (out == NULL)) {
        rc = LOGSYS_ERR_PARAM;
    } else {
        errno = 0;
        v     = strtod(s, &endp);
        if ((endp == s) || (errno != 0) || (v < lo) || (v > hi)) {
            rc = LOGSYS_ERR_PARAM;
        } else {
            *out = v;
        }
    }
    return rc;
}

int main(int argc, char **argv)
{
    int       exit_code = 0;
    Pipeline  p;
    int       stdin_mode = 0;
    int       opt;
    bool_t    init_done  = LOGSYS_FALSE;

    if ((argv == NULL) || (argv[0] == NULL)) {
        exit_code = 1;
    } else if (pipeline_init(&p) != LOGSYS_OK) {
        (void)fprintf(stderr, "pipeline_init failed\n");
        exit_code = 1;
    } else {
        init_done = LOGSYS_TRUE;

        /* Environment defaults — these are the preferred channel for
         * secrets. */
        {
            const char *env_ep  = getenv("LOGSYS_ENDPOINT");
            const char *env_key = getenv("LOGSYS_API_KEY");
            const char *env_ale = getenv("LOGSYS_ALERT_ENDPOINT");
            const char *env_dry = getenv("LOGSYS_DRY_RUN");

            if (env_ep != NULL) {
                (void)snprintf(p.uploader.endpoint,
                               sizeof(p.uploader.endpoint), "%s", env_ep);
            }
            if (env_key != NULL) {
                (void)snprintf(p.uploader.api_key,
                               sizeof(p.uploader.api_key), "%s", env_key);
            }
            if (env_ale != NULL) {
                (void)snprintf(p.monitor.alert_endpoint,
                               sizeof(p.monitor.alert_endpoint), "%s", env_ale);
            }
            if ((env_dry != NULL) &&
                ((env_dry[0] == '1') || (env_dry[0] == 't') ||
                 (env_dry[0] == 'y'))) {
                p.uploader.dry_run = LOGSYS_TRUE;
            }
        }

        while ((opt = getopt(argc, argv, "w:e:k:A:nsi:h")) != -1) {
            switch (opt) {
                case 'w':
                    if (collector_add_file(&p.collector, optarg) != LOGSYS_OK) {
                        (void)fprintf(stderr,
                            "warning: cannot add watch path '%s'\n", optarg);
                    }
                    break;
                case 'e':
                    (void)snprintf(p.uploader.endpoint,
                                   sizeof(p.uploader.endpoint), "%s", optarg);
                    break;
                case 'k':
                    (void)snprintf(p.uploader.api_key,
                                   sizeof(p.uploader.api_key), "%s", optarg);
                    scrub_arg(optarg);   /* CWE-200 */
                    break;
                case 'A':
                    (void)snprintf(p.monitor.alert_endpoint,
                                   sizeof(p.monitor.alert_endpoint),
                                   "%s", optarg);
                    break;
                case 'n':
                    p.uploader.dry_run = LOGSYS_TRUE;
                    break;
                case 's':
                    stdin_mode = 1;
                    break;
                case 'i': {
                    double v = 5.0;
                    if (parse_double_range(optarg, 1.0, 600.0, &v) != LOGSYS_OK) {
                        (void)fprintf(stderr,
                            "invalid -i value (range 1..600 seconds)\n");
                        exit_code = 1;
                    } else {
                        p.flush_interval_ms = (uint32_t)(v * 1000.0);
                    }
                    break;
                }
                case 'h':
                    usage(argv[0]);
                    exit_code = 0;
                    goto cleanup;        /* MISRA 15.1 deviation: cleanup */
                default:
                    usage(argv[0]);
                    exit_code = 1;
                    goto cleanup;
            }
        }

        if (exit_code == 0) {
            if (pipeline_start(&p) != LOGSYS_OK) {
                (void)fprintf(stderr, "pipeline_start failed\n");
                exit_code = 1;
            } else if (stdin_mode != 0) {
                char   line[EVT_MSG_MAX];
                bool_t truncated = LOGSYS_FALSE;
                while (collector_read_line(stdin, line, sizeof(line),
                                           &truncated) == LOGSYS_OK) {
                    LogEvent evt;
                    if (evt_from_line(line, "stdin", &evt) == LOGSYS_OK) {
                        if (truncated == LOGSYS_TRUE) {
                            (void)evt_add_tag(&evt, "truncated", "1");
                        }
                        /* Detection at ingest; FULL = backpressure drop
                         * already counted in rb stats. */
                        (void)pipeline_emit(&p, &evt);
                    }
                }
            } else {
                (void)pipeline_run_until_signal(&p);
            }
            (void)pipeline_stop(&p);
        }
    }

cleanup:
    if (init_done == LOGSYS_TRUE) {
        (void)pipeline_destroy(&p);
    }
    return exit_code;
}
