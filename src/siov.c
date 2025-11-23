#include <stdio.h>
#include <string.h>
#include "siov.h"

static void transcript_hash(siov_scalar_t *h, const uint8_t *msg, size_t msg_len,
                            const uint8_t *ts, size_t ts_len) {
    uint8_t buf[256];
    size_t len = 0;
    const uint8_t tag_msg = 0xA0, tag_ts = 0xA1;
    if (msg_len + ts_len + 2 > sizeof(buf)) {
        msg_len = sizeof(buf) / 2;
        ts_len = sizeof(buf) / 2 - 2;
    }
    buf[len++] = tag_msg;
    memcpy(buf + len, msg, msg_len);
    len += msg_len;
    buf[len++] = tag_ts;
    memcpy(buf + len, ts, ts_len);
    len += ts_len;
    siov_hash_to_scalar(h, buf, len);
}

int siov_setup(siov_params_t *params) {
    if (siov_g1_generator(&params->g1_generator) != 0) return -1;
    if (siov_g2_generator(&params->g2_generator) != 0) return -1;
    if (siov_scalar_random(&params->master_secret) != 0) return -1;
    if (siov_scalar_random(&params->master_trapdoor) != 0) return -1;
    siov_g2_mul(&params->pub_trapdoor, &params->g2_generator, &params->master_trapdoor);
    siov_pairing(&params->pairing_generator, &params->g1_generator, &params->g2_generator);
    return 0;
}

int siov_extract(siov_user_secret_t *usr, const siov_params_t *params, const uint8_t *id, size_t id_len) {
    siov_hash_to_g1(&usr->aid, id, id_len);
    siov_g1_mul(&usr->sk, &usr->aid, &params->master_secret);
    siov_g2_mul(&usr->pk, &params->g2_generator, &params->master_trapdoor);
    return 0;
}

int siov_sign(siov_signature_t *sig, const siov_params_t *params, const siov_user_secret_t *usr,
              const uint8_t *msg, size_t msg_len, const uint8_t *ts, size_t ts_len) {
    memset(sig, 0, sizeof(*sig));
    siov_scalar_t u, h;
    siov_scalar_random(&u);
    transcript_hash(&h, msg, msg_len, ts, ts_len);

    /* U = u * P */
    siov_g1_mul(&sig->U, &params->g1_generator, &u);

    /* gamma = h * SK */
    siov_g1_mul(&sig->gamma, &usr->sk, &h);

    /* alpha = e(U, Q) */
    siov_pairing(&sig->alpha, &sig->U, &params->g2_generator);

    /* beta mirrors gamma for now (skeleton). */
    sig->beta = sig->gamma;

    /* Trace tokens mirror identity */
    sig->C1 = usr->aid;
    sig->C2 = params->g1_generator;
    return 0;
}

int siov_verify(const siov_signature_t *sig, const siov_params_t *params,
               const uint8_t *msg, size_t msg_len, const uint8_t *ts, size_t ts_len) {
    (void)msg; (void)msg_len; (void)ts; (void)ts_len;
    siov_gt_t lhs, rhs;
    siov_pairing(&lhs, &sig->gamma, &params->g2_generator);
    siov_pairing(&rhs, &sig->U, &params->pub_trapdoor);
    return siov_gt_is_equal(&lhs, &rhs);
}

int siov_verify_batch(const siov_signature_t *sigs, const siov_params_t *params,
                     const uint8_t **msgs, const size_t *msg_lens,
                     const uint8_t **tss, const size_t *ts_lens, size_t n) {
    size_t ok = 0;
    for (size_t i = 0; i < n; i++) {
        ok += siov_verify(&sigs[i], params, msgs[i], msg_lens[i], tss[i], ts_lens[i]);
    }
    return ok == n;
}

int siov_encrypt(siov_ciphertext_t *ct, const siov_params_t *params,
                const siov_g1_t *identity_hash,
                const uint8_t *msg, size_t msg_len) {
    (void)msg; (void)msg_len;
    siov_scalar_t r;
    siov_scalar_random(&r);
    siov_g1_mul(&ct->C1, &params->g1_generator, &r);
    siov_pairing(&ct->C2, identity_hash, &params->pub_trapdoor);
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
