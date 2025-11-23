#include <stdio.h>
#include <string.h>
#include "siov_trace.h"
#include "siov_miracl.h"

bool siov_trace_signature(const siov_signature_t *sig, const siov_params_t *params,
                          const uint8_t *msg, size_t msg_len,
                          const uint8_t *ts, size_t ts_len, bool verbose) {
    char buf[1024];
    siov_scalar_t h_td;
    siov_gt_t lhs, rhs_pair, rhs;
    siov_g2_t q2_h;

    /* Compute equation terms. */
    /* h_td = H_td(TD) using the same concatenation strategy as the main path */
    uint8_t concat[512];
    size_t len = 0;
    if (msg_len + ts_len > sizeof(concat)) {
        msg_len = sizeof(concat) / 2;
        ts_len = sizeof(concat) / 2;
    }
    memcpy(concat + len, msg, msg_len);
    len += msg_len;
    memcpy(concat + len, ts, ts_len);
    len += ts_len;
    siov_hash_to_scalar(&h_td, concat, len);
    siov_g2_mul(&q2_h, &params->pub_g2, &h_td);
    siov_pairing(&lhs, &sig->sigma2, &params->g2_generator);
    siov_pairing(&rhs_pair, &sig->sigma3, &q2_h);
    siov_gt_mul(&rhs, &sig->sigma1, &rhs_pair);

    if (verbose) {
        siov_scalar_to_hex(&h_td, buf, sizeof(buf));
        printf("h_td: %s\n", buf);
        siov_g1_to_hex(&sig->sigma2, buf, sizeof(buf));
        printf("sigma2: %s\n", buf);
        siov_g1_to_hex(&sig->sigma3, buf, sizeof(buf));
        printf("sigma3: %s\n", buf);
        siov_gt_to_hex(&sig->sigma1, buf, sizeof(buf));
        printf("sigma1: %s\n", buf);
        siov_g2_to_hex(&q2_h, buf, sizeof(buf));
        printf("h_td * Q2: %s\n", buf);
        siov_gt_to_hex(&lhs, buf, sizeof(buf));
        printf("LHS = e(sigma2, P2): %s\n", buf);
        siov_gt_to_hex(&rhs_pair, buf, sizeof(buf));
        printf("pair(sigma3, h_td*Q2): %s\n", buf);
        siov_gt_to_hex(&rhs, buf, sizeof(buf));
        printf("RHS = sigma1 * pair(...): %s\n", buf);
    }

    return siov_gt_is_equal(&lhs, &rhs);
}
