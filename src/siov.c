#include <stdio.h>
#include <string.h>
#include "siov.h"

static void hash_vehicle_ad(siov_scalar_t *h, const uint8_t *vad, size_t vad_len) {
    siov_hash_to_scalar(h, vad, vad_len);
}

static void hash_td(siov_scalar_t *h, const uint8_t *msg, size_t msg_len,
                    const uint8_t *ts, size_t ts_len) {
    uint8_t buf[512];
    size_t copy_len = 0;
    if (msg_len + ts_len > sizeof(buf)) {
        msg_len = sizeof(buf) / 2;
        ts_len = sizeof(buf) / 2;
    }
    memcpy(buf + copy_len, msg, msg_len);
    copy_len += msg_len;
    memcpy(buf + copy_len, ts, ts_len);
    copy_len += ts_len;
    siov_hash_to_scalar(h, buf, copy_len);
}

static int random_scalar_nonzero(siov_scalar_t *x) {
    do {
        if (siov_scalar_random(x) != 0) return -1;
    } while (siov_scalar_is_zero(x));
    return 0;
}

int siov_setup(siov_params_t *params) {
    if (siov_g1_generator(&params->g1_generator) != 0) return -1;
    if (siov_g2_generator(&params->g2_generator) != 0) return -1;
    if (random_scalar_nonzero(&params->master_secret) != 0) return -1;

    /* Q = sP and Q2 = sP2 */
    siov_g1_mul(&params->pub_g1, &params->g1_generator, &params->master_secret);
    siov_g2_mul(&params->pub_g2, &params->g2_generator, &params->master_secret);

    /* g = e(P, P2) */
    siov_pairing(&params->pairing_generator, &params->g1_generator, &params->g2_generator);
    return 0;
}

int siov_extract(siov_user_secret_t *usr, const siov_params_t *params, const uint8_t *id, size_t id_len) {
    memset(usr, 0, sizeof(*usr));
    usr->vad_len = id_len > sizeof(usr->vad) ? sizeof(usr->vad) : id_len;
    memcpy(usr->vad, id, usr->vad_len);

    hash_vehicle_ad(&usr->h_vad, id, id_len);
    siov_g1_mul(&usr->pk_g1, &params->g1_generator, &usr->h_vad);
    siov_g2_mul(&usr->pk_g2, &params->g2_generator, &usr->h_vad);
    siov_g1_mul(&usr->sk, &usr->pk_g1, &params->master_secret);
    return 0;
}

int siov_sign(siov_signature_t *sig, const siov_params_t *params, const siov_user_secret_t *usr,
              const uint8_t *msg, size_t msg_len, const uint8_t *ts, size_t ts_len) {
    memset(sig, 0, sizeof(*sig));
    siov_scalar_t r, k, t, h_td, rk, th, rt;

    if (random_scalar_nonzero(&r) != 0 || random_scalar_nonzero(&k) != 0 || random_scalar_nonzero(&t) != 0) {
        return -1;
    }

    hash_td(&h_td, msg, msg_len, ts, ts_len);

    /* sigma1 = g^r */
    siov_gt_pow(&sig->sigma1, &params->pairing_generator, &r);

    /* PPr_AD1 = r * SK */
    siov_g1_t ppr_ad1;
    siov_g1_mul(&ppr_ad1, &usr->sk, &r);

    /* PPr_AD2 = r t * PK */
    siov_scalar_mul(&rt, &r, &t);
    siov_g1_mul(&sig->sigma3, &usr->pk_g1, &rt);

    /* sigma2 = (r k) P + (t h_td) PPr_AD1 */
    siov_scalar_mul(&rk, &r, &k);
    siov_scalar_mul(&th, &t, &h_td);

    siov_g1_t term1, term2;
    siov_g1_mul(&term1, &params->g1_generator, &rk);
    siov_g1_mul(&term2, &ppr_ad1, &th);
    siov_g1_add(&sig->sigma2, &term1, &term2);

    return 0;
}

int siov_verify(const siov_signature_t *sig, const siov_params_t *params,
               const uint8_t *msg, size_t msg_len, const uint8_t *ts, size_t ts_len) {
    siov_scalar_t h_td;
    hash_td(&h_td, msg, msg_len, ts, ts_len);

    /* Q2_h = h_td * Q2 */
    siov_g2_t q2_h;
    siov_g2_mul(&q2_h, &params->pub_g2, &h_td);

    siov_gt_t lhs, rhs_pair, rhs;
    siov_pairing(&lhs, &sig->sigma2, &params->g2_generator);
    siov_pairing(&rhs_pair, &sig->sigma3, &q2_h);
    siov_gt_mul(&rhs, &sig->sigma1, &rhs_pair);

    return siov_gt_is_equal(&lhs, &rhs);
}

int siov_verify_batch(const siov_signature_t *sigs, const siov_params_t *params,
                     const uint8_t **msgs, const size_t *msg_lens,
                     const uint8_t **tss, const size_t *ts_lens, size_t n) {
    siov_g1_t S2, S3;
    siov_gt_t Gbeta;
    siov_g1_zero(&S2);
    siov_g1_zero(&S3);
    siov_gt_one(&Gbeta);

    for (size_t i = 0; i < n; i++) {
        siov_scalar_t beta_i, h_i, beta_hi;
        if (random_scalar_nonzero(&beta_i) != 0) return 0;
        hash_td(&h_i, msgs[i], msg_lens[i], tss[i], ts_lens[i]);
        siov_scalar_mul(&beta_hi, &beta_i, &h_i);

        siov_g1_t tmp;
        siov_g1_mul(&tmp, &sigs[i].sigma2, &beta_i);
        siov_g1_add(&S2, &S2, &tmp);

        siov_g1_mul(&tmp, &sigs[i].sigma3, &beta_hi);
        siov_g1_add(&S3, &S3, &tmp);

        siov_gt_t sigma1_beta;
        siov_gt_pow(&sigma1_beta, &sigs[i].sigma1, &beta_i);
        siov_gt_mul(&Gbeta, &Gbeta, &sigma1_beta);
    }

    siov_gt_t lhs, rhs_pair, rhs;
    siov_pairing(&lhs, &S2, &params->g2_generator);
    siov_pairing(&rhs_pair, &S3, &params->pub_g2);
    siov_gt_mul(&rhs, &Gbeta, &rhs_pair);

    return siov_gt_is_equal(&lhs, &rhs);
}

int siov_encrypt(siov_ciphertext_t *ct, const siov_params_t *params,
                const siov_g1_t *identity_hash,
                const uint8_t *msg, size_t msg_len) {
    (void)msg; (void)msg_len;
    siov_scalar_t r;
    random_scalar_nonzero(&r);
    siov_g1_mul(&ct->C1, &params->g1_generator, &r);
    siov_pairing(&ct->C2, identity_hash, &params->pub_g2);
    return 0;
}

int siov_decrypt(uint8_t *out, size_t out_len, const siov_ciphertext_t *ct,
                const siov_user_secret_t *usr) {
    (void)ct;
    memset(out, 0, out_len);
    /* Placeholder decryption. */
    if (out_len > 0) out[0] = 0x42;
    (void)usr;
    return 0;
}
