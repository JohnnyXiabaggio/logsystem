#include "collector.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <time.h>
#include <pthread.h>

/* ------------------------------------------------------------------ */
/* File tail helpers                                                   */
/* ------------------------------------------------------------------ */

static void tail_open(FileTailState *st) {
    if (st->fp) { fclose(st->fp); st->fp = NULL; }
    st->fp = fopen(st->path, "r");
    if (!st->fp) return;
    /* seek to end so we only capture new lines */
    fseek(st->fp, 0, SEEK_END);
    st->pos       = ftell(st->fp);
    st->last_size = st->pos;
}

static void tail_poll(FileTailState *st, RingBuffer *rb) {
    struct stat sb;
    if (stat(st->path, &sb) < 0) {
        if (st->fp) { fclose(st->fp); st->fp = NULL; }
        return;
    }
    if (!st->fp) {
        tail_open(st);
        return;
    }
    /* log rotation: file shrank */
    if ((long)sb.st_size < st->last_size) {
        tail_open(st);
        return;
    }
    st->last_size = (long)sb.st_size;

    fseek(st->fp, st->pos, SEEK_SET);
    char line[EVT_MSG_MAX];
    while (fgets(line, sizeof(line), st->fp)) {
        LogEvent evt;
        if (evt_from_line(line, st->path, &evt) == 0)
            rb_push(rb, &evt);
    }
    st->pos = ftell(st->fp);
}

/* ------------------------------------------------------------------ */
/* Background thread                                                   */
/* ------------------------------------------------------------------ */

static void *collector_thread(void *arg) {
    Collector *c = (Collector *)arg;
    FileTailState states[COLLECTOR_MAX_FILES];
    memset(states, 0, sizeof(states));

    for (int i = 0; i < c->nfiles; i++) {
        snprintf(states[i].path, sizeof(states[i].path), "%s", c->paths[i]);
        tail_open(&states[i]);
    }

    while (c->running) {
        for (int i = 0; i < c->nfiles; i++)
            tail_poll(&states[i], c->rb);

        struct timespec ts = {
            .tv_sec  = c->poll_ms / 1000,
            .tv_nsec = (long)(c->poll_ms % 1000) * 1000000L
        };
        nanosleep(&ts, NULL);
    }

    for (int i = 0; i < c->nfiles; i++)
        if (states[i].fp) fclose(states[i].fp);

    return NULL;
}

/* ------------------------------------------------------------------ */
/* Public API                                                          */
/* ------------------------------------------------------------------ */

int collector_init(Collector *c, RingBuffer *rb, int poll_ms) {
    memset(c, 0, sizeof(*c));
    c->rb      = rb;
    c->poll_ms = poll_ms > 0 ? poll_ms : 1000;
    c->running = 0;
    return 0;
}

int collector_add_file(Collector *c, const char *path) {
    if (c->nfiles >= COLLECTOR_MAX_FILES) return -1;
    c->paths[c->nfiles] = strdup(path);
    if (!c->paths[c->nfiles]) return -1;
    c->nfiles++;
    return 0;
}

void collector_start(Collector *c) {
    c->running = 1;
    pthread_create(&c->thread, NULL, collector_thread, c);
}

void collector_stop(Collector *c) {
    c->running = 0;
    pthread_join(c->thread, NULL);
}

void collector_free(Collector *c) {
    for (int i = 0; i < c->nfiles; i++) free(c->paths[i]);
}

void collector_emit(Collector *c, const char *msg, Severity sev, const char *src) {
    LogEvent evt;
    evt_init(&evt, msg, sev, src);
    rb_push(c->rb, &evt);
}
