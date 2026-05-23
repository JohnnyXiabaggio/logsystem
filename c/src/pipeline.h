#ifndef PIPELINE_H
#define PIPELINE_H

#include "ring_buffer.h"
#include "collector.h"
#include "uploader.h"
#include "monitor.h"
#include <pthread.h>

#define FLUSH_BATCH 500       /* events per uploader call */

typedef struct {
    RingBuffer  rb;
    Collector   collector;
    Uploader    uploader;
    Monitor     monitor;

    /* flush thread */
    pthread_t        flush_thread;
    volatile int     running;
    double           flush_interval_sec;

    /* health-report thread */
    pthread_t        health_thread;
    double           health_interval_sec;
} Pipeline;

/* cfg is shallow — fields copied in */
int  pipeline_init(Pipeline *p);
void pipeline_start(Pipeline *p);
void pipeline_stop(Pipeline *p);
void pipeline_free(Pipeline *p);

/* Block until SIGINT or SIGTERM */
void pipeline_run_until_signal(Pipeline *p);

#endif /* PIPELINE_H */
