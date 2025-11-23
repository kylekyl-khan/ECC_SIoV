#ifndef SIOV_H
#define SIOV_H

#include <stddef.h>
#include <stdint.h>
#include "siov_miracl.h"

/* High-level SIOV protocol structures. */
typedef struct {
    siov_scalar_t master_secret; /* s */
    siov_scalar_t master_trapdoor; /* x */
    siov_g1_t g1_generator; /* P */
    siov_g2_t g2_generator; /* Q */
    siov_g2_t pub_trapdoor; /* x*Q */
    siov_gt_t pairing_generator; /* e(P,Q) */
} siov_params_t;

typedef struct {
    siov_g1_t aid; /* hash of identity */
    siov_g1_t sk;  /* s * AID */
    siov_g2_t pk;  /* x * SK (in G2 for demo) */
} siov_user_secret_t;

typedef struct {
    siov_g1_t U;
    siov_gt_t alpha;
    siov_g1_t beta;
    siov_g1_t gamma;
    siov_g1_t C1;
    siov_g1_t C2;
} siov_signature_t;

typedef struct {
    siov_g1_t C1;
    siov_gt_t C2;
} siov_ciphertext_t;

/* Setup and key extraction */
int siov_setup(siov_params_t *params);
int siov_extract(siov_user_secret_t *usr, const siov_params_t *params, const uint8_t *id, size_t id_len);

/* Signing and verification */
int siov_sign(siov_signature_t *sig, const siov_params_t *params, const siov_user_secret_t *usr,
              const uint8_t *msg, size_t msg_len, const uint8_t *ts, size_t ts_len);
int siov_verify(const siov_signature_t *sig, const siov_params_t *params,
               const uint8_t *msg, size_t msg_len, const uint8_t *ts, size_t ts_len);

/* Batch verification */
int siov_verify_batch(const siov_signature_t *sigs, const siov_params_t *params,
                     const uint8_t **msgs, const size_t *msg_lens,
                     const uint8_t **tss, const size_t *ts_lens, size_t n);

/* Encryption / decryption skeleton */
int siov_encrypt(siov_ciphertext_t *ct, const siov_params_t *params,
                const siov_g1_t *identity_hash,
                const uint8_t *msg, size_t msg_len);
int siov_decrypt(uint8_t *out, size_t out_len, const siov_ciphertext_t *ct,
                const siov_user_secret_t *usr);

#endif /* SIOV_H */
