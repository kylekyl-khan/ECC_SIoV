#include "siov_bench.h"

void siov_timer_start(siov_timer_t *t) {
    clock_gettime(CLOCK_MONOTONIC, &t->start);
}

void siov_timer_stop(siov_timer_t *t) {
    clock_gettime(CLOCK_MONOTONIC, &t->end);
}

double siov_timer_ms(const siov_timer_t *t) {
    long sec = t->end.tv_sec - t->start.tv_sec;
    long nsec = t->end.tv_nsec - t->start.tv_nsec;
    return (double)sec * 1000.0 + (double)nsec / 1e6;
}
