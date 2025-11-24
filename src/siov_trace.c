#include <stdio.h>
#include <string.h>
#include "siov_trace.h"
#include "siov_miracl.h"

bool siov_trace_signature(const siov_signature_t *sig, const siov_params_t *params,
                          const uint8_t *msg, size_t msg_len,
                          const uint8_t *ts, size_t ts_len, bool verbose) {
    (void)msg; (void)msg_len; (void)ts; (void)ts_len;
    char buf[1024];
    siov_gt_t lhs, rhs;
    siov_pairing(&lhs, &sig->gamma, &params->g2_generator);
    siov_pairing(&rhs, &sig->U, &params->pub_trapdoor);

    if (verbose) {
        siov_g1_to_hex(&sig->U, buf, sizeof(buf));
        printf("U: %s\n", buf);
        siov_g1_to_hex(&sig->gamma, buf, sizeof(buf));
        printf("gamma: %s\n", buf);
        siov_gt_to_hex(&lhs, buf, sizeof(buf));
        printf("pair(gamma, Q): %s\n", buf);
        siov_gt_to_hex(&rhs, buf, sizeof(buf));
        printf("pair(U, xQ): %s\n", buf);
    }

    return siov_gt_is_equal(&lhs, &rhs);
}
