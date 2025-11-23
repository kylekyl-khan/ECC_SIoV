#ifndef SIOV_BENCH_H
#define SIOV_BENCH_H

#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 199309L
#endif

#include <stddef.h>
#include <stdint.h>
#include <time.h>

typedef struct {
    struct timespec start;
    struct timespec end;
} siov_timer_t;

void siov_timer_start(siov_timer_t *t);
void siov_timer_stop(siov_timer_t *t);
double siov_timer_ms(const siov_timer_t *t);

#endif /* SIOV_BENCH_H */
