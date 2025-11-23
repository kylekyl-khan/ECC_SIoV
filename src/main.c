#include <stdio.h>
#include <stdlib.h>
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

    const uint8_t *id = (const uint8_t *)"demo-identity";
    siov_user_secret_t user;
    siov_extract(&user, &params, id, 13);

    siov_signature_t *sigs = calloc(opts->count, sizeof(*sigs));
    const uint8_t **msgs = calloc(opts->count, sizeof(*msgs));
    size_t *mlens = calloc(opts->count, sizeof(*mlens));
    const uint8_t **tss = calloc(opts->count, sizeof(*tss));
    size_t *tlens = calloc(opts->count, sizeof(*tlens));

    if (!sigs || !msgs || !mlens || !tss || !tlens) {
        fprintf(stderr, "allocation failure\n");
        goto cleanup;
    }

    for (size_t i = 0; i < opts->count; i++) {
        msgs[i] = (const uint8_t *)"hello-siov";
        mlens[i] = 10;
        tss[i] = (const uint8_t *)"ts";
        tlens[i] = 2;
        siov_sign(&sigs[i], &params, &user, msgs[i], mlens[i], tss[i], tlens[i]);
    }

    siov_timer_t t;
    double verify_ms = 0.0;
    if (opts->verify) {
        siov_timer_start(&t);
        for (size_t i = 0; i < opts->count; i++) {
            if (!siov_verify(&sigs[i], &params, msgs[i], mlens[i], tss[i], tlens[i])) {
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
        siov_verify_batch(sigs, &params, msgs, mlens, tss, tlens, opts->count);
        siov_timer_stop(&t);
        printf("Batch verify: %.2f ms\n", siov_timer_ms(&t));
    }

    printf("Signed %zu messages. Verify time: %.2f ms\n", opts->count, verify_ms);

cleanup:
    free(sigs);
    free((void *)msgs);
    free(mlens);
    free((void *)tss);
    free(tlens);
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
