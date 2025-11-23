#include <stdio.h>
#include <string.h>
#include <time.h>
#include "siov_miracl.h"

#include "arch.h"
#include "core.h"
#include "randapi.h"
#include "pair_BN254.h"
#include "ecp_BN254.h"
#include "ecp2_BN254.h"
#include "fp12_BN254.h"
#include "big_256_56.h"
#include "hash256.h"

static csprng rng;
static int rng_ready = 0;

static void scalar_store(siov_scalar_t *dst, const BIG_256_56 src) {
    BIG_256_56_toBytes(dst->bytes, src);
}

static void scalar_load(BIG_256_56 dst, const siov_scalar_t *src) {
    BIG_256_56_fromBytes(dst, src->bytes);
}

static void g1_store(siov_g1_t *dst, const ECP_BN254 *p) {
    octet o = {.len = 0, .max = sizeof(dst->bytes), .val = (char *)dst->bytes};
    ECP_BN254_toOctet(&o, (ECP_BN254 *)p, false);
}

static int g1_load(ECP_BN254 *p, const siov_g1_t *src) {
    octet o = {.len = sizeof(src->bytes), .max = sizeof(src->bytes), .val = (char *)src->bytes};
    return ECP_BN254_fromOctet(p, &o);
}

static void g2_store(siov_g2_t *dst, const ECP2_BN254 *p) {
    octet o = {.len = 0, .max = sizeof(dst->bytes), .val = (char *)dst->bytes};
    ECP2_BN254_toOctet(&o, (ECP2_BN254 *)p, false);
}

static int g2_load(ECP2_BN254 *p, const siov_g2_t *src) {
    octet o = {.len = sizeof(src->bytes), .max = sizeof(src->bytes), .val = (char *)src->bytes};
    return ECP2_BN254_fromOctet(p, &o);
}

static void gt_store(siov_gt_t *dst, const FP12_BN254 *gt) {
    octet o = {.len = 0, .max = sizeof(dst->bytes), .val = (char *)dst->bytes};
    FP12_BN254_toOctet(&o, (FP12_BN254 *)gt);
}

static int gt_load(FP12_BN254 *gt, const siov_gt_t *src) {
    octet o = {.len = sizeof(src->bytes), .max = sizeof(src->bytes), .val = (char *)src->bytes};
    return FP12_BN254_fromOctet(gt, &o);
}

static void seed_rng(void) {
    char raw[32];
    for (size_t i = 0; i < sizeof(raw); i++) {
        raw[i] = (char)(clock() + i);
    }
    RAND_seed(&rng, sizeof(raw), raw);
    rng_ready = 1;
}

int siov_miracl_init(void) {
    seed_rng();
    return rng_ready ? 0 : -1;
}

void siov_miracl_cleanup(void) {
    (void)rng_ready;
}

int siov_scalar_random(siov_scalar_t *x) {
    BIG_256_56 r, order;
    BIG_256_56_rcopy(order, CURVE_Order_BN254);
    BIG_256_56_randtrunc(r, order, 2 * CURVE_SECURITY_BN254, &rng);
    scalar_store(x, r);
    return 0;
}

int siov_scalar_from_hash(siov_scalar_t *x, const uint8_t *msg, size_t msg_len) {
    hash256 h;
    HASH256_init(&h);
    for (size_t i = 0; i < msg_len; i++) {
        HASH256_process(&h, msg[i]);
    }
    uint8_t digest[32];
    HASH256_hash(&h, digest);
    BIG_256_56 r, order;
    BIG_256_56_rcopy(order, CURVE_Order_BN254);
    BIG_256_56_fromBytesLen(r, digest, sizeof(digest));
    BIG_256_56_mod(r, order);
    scalar_store(x, r);
    return 0;
}

int siov_scalar_mul(siov_scalar_t *out, const siov_scalar_t *a, const siov_scalar_t *b) {
    BIG_256_56 x, y, order, z;
    scalar_load(x, a);
    scalar_load(y, b);
    BIG_256_56_rcopy(order, CURVE_Order_BN254);
    BIG_256_56_modmul(z, x, y, order);
    scalar_store(out, z);
    return 0;
}

int siov_scalar_add(siov_scalar_t *out, const siov_scalar_t *a, const siov_scalar_t *b) {
    BIG_256_56 x, y, order;
    scalar_load(x, a);
    scalar_load(y, b);
    BIG_256_56_rcopy(order, CURVE_Order_BN254);
    BIG_256_56_add(x, x, y);
    BIG_256_56_mod(x, order);
    scalar_store(out, x);
    return 0;
}

int siov_scalar_is_zero(const siov_scalar_t *x) {
    BIG_256_56 v;
    scalar_load(v, x);
    return BIG_256_56_iszilch(v);
}

int siov_g1_generator(siov_g1_t *g1) {
    ECP_BN254 p;
    ECP_BN254_generator(&p);
    g1_store(g1, &p);
    return 0;
}

int siov_g2_generator(siov_g2_t *g2) {
    ECP2_BN254 q;
    ECP2_BN254_generator(&q);
    g2_store(g2, &q);
    return 0;
}

int siov_g1_mul(siov_g1_t *out, const siov_g1_t *p, const siov_scalar_t *x) {
    ECP_BN254 base;
    if (!g1_load(&base, p)) return -1;
    BIG_256_56 k;
    scalar_load(k, x);
    ECP_BN254_mul(&base, k);
    g1_store(out, &base);
    return 0;
}

int siov_g2_mul(siov_g2_t *out, const siov_g2_t *p, const siov_scalar_t *x) {
    ECP2_BN254 base;
    if (!g2_load(&base, p)) return -1;
    BIG_256_56 k;
    scalar_load(k, x);
    ECP2_BN254_mul(&base, k);
    g2_store(out, &base);
    return 0;
}

int siov_g1_add(siov_g1_t *out, const siov_g1_t *a, const siov_g1_t *b) {
    ECP_BN254 pa, pb;
    if (!g1_load(&pa, a)) return -1;
    if (!g1_load(&pb, b)) return -1;
    ECP_BN254_add(&pa, &pb);
    g1_store(out, &pa);
    return 0;
}

int siov_g1_zero(siov_g1_t *out) {
    ECP_BN254 p;
    ECP_BN254_inf(&p);
    g1_store(out, &p);
    return 0;
}

int siov_pairing(siov_gt_t *out, const siov_g1_t *p, const siov_g2_t *q) {
    ECP_BN254 g1;
    ECP2_BN254 g2;
    if (!g1_load(&g1, p)) return -1;
    if (!g2_load(&g2, q)) return -1;
    FP12_BN254 gt;
    PAIR_BN254_ate(&gt, &g2, &g1);
    PAIR_BN254_fexp(&gt);
    gt_store(out, &gt);
    return 0;
}

int siov_gt_mul(siov_gt_t *out, const siov_gt_t *a, const siov_gt_t *b) {
    FP12_BN254 x, y;
    if (!gt_load(&x, a) || !gt_load(&y, b)) return -1;
    FP12_BN254_mul(&x, &y);
    gt_store(out, &x);
    return 0;
}

int siov_gt_pow(siov_gt_t *out, const siov_gt_t *a, const siov_scalar_t *x) {
    FP12_BN254 gt;
    BIG_256_56 k;
    if (!gt_load(&gt, a)) return -1;
    scalar_load(k, x);
    FP12_BN254_pow(&gt, &gt, k);
    gt_store(out, &gt);
    return 0;
}

int siov_gt_one(siov_gt_t *out) {
    FP12_BN254 gt;
    FP12_BN254_one(&gt);
    gt_store(out, &gt);
    return 0;
}

int siov_gt_is_equal(const siov_gt_t *a, const siov_gt_t *b) {
    FP12_BN254 x, y;
    if (!gt_load(&x, a) || !gt_load(&y, b)) return 0;
    return FP12_BN254_equals(&x, &y);
}

int siov_gt_is_one(const siov_gt_t *a) {
    FP12_BN254 x;
    if (!gt_load(&x, a)) return 0;
    return FP12_BN254_isunity(&x);
}

int siov_hash_to_scalar(siov_scalar_t *x, const uint8_t *msg, size_t msg_len) {
    return siov_scalar_from_hash(x, msg, msg_len);
}

int siov_hash_to_g1(siov_g1_t *p, const uint8_t *msg, size_t msg_len) {
    octet o = {.len = (int)msg_len, .max = (int)msg_len, .val = (char *)msg};
    ECP_BN254 point;
    ECP_BN254_mapit(&point, &o);
    g1_store(p, &point);
    return 0;
}

static void hex_encode(const uint8_t *buf, size_t len, char *out, size_t out_len) {
    static const char *hex = "0123456789abcdef";
    size_t idx = 0;
    for (size_t i = 0; i < len && idx + 2 < out_len; i++) {
        out[idx++] = hex[(buf[i] >> 4) & 0xF];
        out[idx++] = hex[buf[i] & 0xF];
    }
    if (idx < out_len) out[idx] = '\0';
}

void siov_g1_to_hex(const siov_g1_t *p, char *out, size_t out_len) {
    hex_encode(p->bytes, sizeof(p->bytes), out, out_len);
}

void siov_g2_to_hex(const siov_g2_t *p, char *out, size_t out_len) {
    hex_encode(p->bytes, sizeof(p->bytes), out, out_len);
}

void siov_gt_to_hex(const siov_gt_t *p, char *out, size_t out_len) {
    hex_encode(p->bytes, sizeof(p->bytes), out, out_len);
}

void siov_scalar_to_hex(const siov_scalar_t *s, char *out, size_t out_len) {
    hex_encode(s->bytes, sizeof(s->bytes), out, out_len);
}
