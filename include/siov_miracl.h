#ifndef SIOV_MIRACL_H
#define SIOV_MIRACL_H

#include <stddef.h>
#include <stdint.h>

/*
 * MIRACL Core integration layer for SIOV.
 *
 * This implementation targets the BN254 pairing-friendly curve
 * (also known as BN-P254) using MIRACL Core's C API.
 */

typedef struct siov_scalar {
    /* BIG_256_56 stores scalars in Z_r. */
    uint8_t bytes[32];
} siov_scalar_t;

typedef struct siov_g1_point {
    /* ECP_BN254 serialization. */
    uint8_t bytes[65];
} siov_g1_t;

typedef struct siov_g2_point {
    /* ECP2_BN254 serialization. */
    uint8_t bytes[129];
} siov_g2_t;

typedef struct siov_gt_elem {
    /* FP12_BN254 serialization. */
    uint8_t bytes[384];
} siov_gt_t;

/* Initialization / teardown */
int siov_miracl_init(void);
void siov_miracl_cleanup(void);

/* Scalar and point operations */
int siov_scalar_random(siov_scalar_t *x);
int siov_scalar_from_hash(siov_scalar_t *x, const uint8_t *msg, size_t msg_len);
int siov_scalar_mul(siov_scalar_t *out, const siov_scalar_t *a, const siov_scalar_t *b);
int siov_scalar_add(siov_scalar_t *out, const siov_scalar_t *a, const siov_scalar_t *b);
int siov_scalar_is_zero(const siov_scalar_t *x);
int siov_g1_generator(siov_g1_t *g1);
int siov_g2_generator(siov_g2_t *g2);
int siov_g1_mul(siov_g1_t *out, const siov_g1_t *p, const siov_scalar_t *x);
int siov_g2_mul(siov_g2_t *out, const siov_g2_t *p, const siov_scalar_t *x);
int siov_g1_add(siov_g1_t *out, const siov_g1_t *a, const siov_g1_t *b);
int siov_g1_zero(siov_g1_t *out);
int siov_pairing(siov_gt_t *out, const siov_g1_t *p, const siov_g2_t *q);
int siov_gt_mul(siov_gt_t *out, const siov_gt_t *a, const siov_gt_t *b);
int siov_gt_pow(siov_gt_t *out, const siov_gt_t *a, const siov_scalar_t *x);
int siov_gt_one(siov_gt_t *out);
int siov_gt_is_equal(const siov_gt_t *a, const siov_gt_t *b);
int siov_gt_is_one(const siov_gt_t *a);

/* Hashing helpers */
int siov_hash_to_scalar(siov_scalar_t *x, const uint8_t *msg, size_t msg_len);
int siov_hash_to_g1(siov_g1_t *p, const uint8_t *msg, size_t msg_len);

/* Utility: hex encoding for tracing */
void siov_g1_to_hex(const siov_g1_t *p, char *out, size_t out_len);
void siov_g2_to_hex(const siov_g2_t *p, char *out, size_t out_len);
void siov_gt_to_hex(const siov_gt_t *p, char *out, size_t out_len);
void siov_scalar_to_hex(const siov_scalar_t *s, char *out, size_t out_len);

#endif /* SIOV_MIRACL_H */
