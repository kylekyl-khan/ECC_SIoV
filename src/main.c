#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "siov_cli.h"
#include "siov_bench.h"
#include "siov.h"
#include "siov_miracl.h"
#include "siov_trace.h"

static void run_single(const siov_cli_opts_t *opts) {
    siov_params_t params;
    if (siov_setup(&params) != 0) {
        fprintf(stderr, "Failed to set up parameters\n");
        return;
    }

    const char *id = "VAD_DEMO_001";
    siov_user_secret_t user;
    siov_extract(&user, &params, (const uint8_t *)id, strlen(id));

    siov_signature_t *sigs = calloc(opts->count, sizeof(*sigs));
    const uint8_t **msgs = calloc(opts->count, sizeof(*msgs));
    size_t *mlens = calloc(opts->count, sizeof(*mlens));
    const uint8_t **tss = calloc(opts->count, sizeof(*tss));
    size_t *tlens = calloc(opts->count, sizeof(*tlens));
    char (*msg_bufs)[64] = calloc(opts->count, sizeof(*msg_bufs));
    char (*ts_bufs)[32] = calloc(opts->count, sizeof(*ts_bufs));

    if (!sigs || !msgs || !mlens || !tss || !tlens || !msg_bufs || !ts_bufs) {
        fprintf(stderr, "allocation failure\n");
        goto cleanup;
    }

    for (size_t i = 0; i < opts->count; i++) {
        snprintf(msg_bufs[i], sizeof(msg_bufs[i]), "traffic-data-%zu", i);
        snprintf(ts_bufs[i], sizeof(ts_bufs[i]), "ts-%zu", i);
        msgs[i] = (const uint8_t *)msg_bufs[i];
        mlens[i] = strlen(msg_bufs[i]);
        tss[i] = (const uint8_t *)ts_bufs[i];
        tlens[i] = strlen(ts_bufs[i]);
    }

    siov_timer_t t;
    double sign_ms = 0.0, verify_ms = 0.0, batch_ms = 0.0;

    siov_timer_start(&t);
    for (size_t i = 0; i < opts->count; i++) {
        siov_sign(&sigs[i], &params, &user, msgs[i], mlens[i], tss[i], tlens[i]);
    }
    siov_timer_stop(&t);
    sign_ms = siov_timer_ms(&t);

    if (opts->verify) {
        siov_timer_start(&t);
        for (size_t i = 0; i < opts->count; i++) {
            int ok = siov_verify(&sigs[i], &params, msgs[i], mlens[i], tss[i], tlens[i]);
            if (!ok) {
                fprintf(stderr, "verify failed at %zu\n", i);
            }
            if (opts->trace && i == 0) {
                siov_trace_signature(&sigs[i], &params, msgs[i], mlens[i], tss[i], tlens[i], true);
            }
        }
        siov_timer_stop(&t);
        verify_ms = siov_timer_ms(&t);
    }

    if (opts->batch && opts->verify) {
        siov_timer_start(&t);
        int batch_ok = siov_verify_batch(sigs, &params, msgs, mlens, tss, tlens, opts->count);
        siov_timer_stop(&t);
        batch_ms = siov_timer_ms(&t);
        printf("Batch verify: %s (%.2f ms)\n", batch_ok ? "ok" : "fail", batch_ms);
    }

    printf("Signed %zu messages. Sign time: %.2f ms Verify time: %.2f ms\n", opts->count, sign_ms, verify_ms);

cleanup:
    free(sigs);
    free((void *)msgs);
    free(mlens);
    free((void *)tss);
    free(tlens);
    free(msg_bufs);
    free(ts_bufs);
}

int main(int argc, char **argv) {
    siov_cli_opts_t opts;
    if (siov_cli_parse(argc, argv, &opts) != 0) {
        siov_cli_usage(argv[0]);
        return 1;
    }

    if (siov_miracl_init() != 0) {
        fprintf(stderr, "Failed to initialize MIRACL Core\n");
        return 1;
    }

    run_single(&opts);

    siov_miracl_cleanup();
    return 0;
}
