#ifndef SIOV_H
#define SIOV_H

#include <stddef.h>
#include <stdint.h>
#include "siov_miracl.h"

/* High-level SIOV protocol structures. */
typedef struct {
    siov_scalar_t master_secret; /* s */
    siov_g1_t g1_generator; /* P */
    siov_g2_t g2_generator; /* P2 */
    siov_g1_t pub_g1; /* Q = sP */
    siov_g2_t pub_g2; /* Q2 = sP2 */
    siov_gt_t pairing_generator; /* g = e(P, P2) */
} siov_params_t;

typedef struct {
    uint8_t vad[64];
    size_t vad_len;
    siov_scalar_t h_vad; /* H_vad(VAD) */
    siov_g1_t pk_g1; /* PK = h_vad * P */
    siov_g2_t pk_g2; /* PK2 = h_vad * P2 */
    siov_g1_t sk;    /* SK = s * PK */
} siov_user_secret_t;

typedef struct {
    siov_gt_t sigma1; /* g^r */
    siov_g1_t sigma2; /* (r k)P + (t h_td) PPr_AD1 */
    siov_g1_t sigma3; /* r t PK */
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
