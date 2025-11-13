// siov_batch_demo.c
// IBE-style anonymous sign with RC-only trace token + Batch Verification (PBC).
// Build: gcc siov_batch_demo.c -lpbc -lgmp -o siov_batch_demo
// Run  : ./siov_batch_demo a.param

#include <pbc/pbc.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    pairing_t pairing;
    element_t P, Q;     // G1
    element_t g;        // GT = e(P,P)
    element_t x, s;     // Zr (RC master secrets)
} sys_t;

typedef struct {
    element_t AID, SK, PK; // G1
} veh_keys_t;

typedef struct {
    element_t U;      // G1 : u*P
    element_t alpha;  // GT : g^(u*h)
    element_t beta;   // G1 : (u*h)P + (h^2)*(u*PK)
    element_t gamma;  // G1 : (u*h)*SK
    element_t C1;     // G1 : r*P
    element_t C2;     // G1 : AID + r*Q
} sig_t;

/*------------------ utils ------------------*/
static void die(const char *m){ fprintf(stderr,"%s\n", m); exit(1); }

static void setup(sys_t *S, const char *param_path){
    FILE *fp = fopen(param_path, "r"); if(!fp) die("open param fail");
    char buf[4096]; size_t n = fread(buf,1,sizeof(buf),fp); fclose(fp);
    if(!n) die("read param fail");
    pairing_init_set_buf(S->pairing, buf, n);
    element_init_G1(S->P, S->pairing);
    element_init_G1(S->Q, S->pairing);
    element_init_GT(S->g, S->pairing);
    element_init_Zr(S->x, S->pairing);
    element_init_Zr(S->s, S->pairing);
    element_random(S->P);
    element_pairing(S->g, S->P, S->P);
    element_random(S->x); element_random(S->s);
    element_mul_zn(S->Q, S->P, S->x); // Q = xP
}

static void veh_keys_init(veh_keys_t *K, pairing_t p){
    element_init_G1(K->AID, p);
    element_init_G1(K->SK,  p);
    element_init_G1(K->PK,  p);
}
static void veh_keygen(veh_keys_t *K, sys_t *S, const char *VID){
    element_from_hash(K->AID, VID, strlen(VID));  // AID = f(VID)
    element_mul_zn(K->SK, K->AID, S->s);         // SK = s*AID
    element_mul_zn(K->PK, K->SK, S->x);          // PK = x*SK
}

static void sig_init(sig_t *sig, pairing_t p){
    element_init_G1(sig->U,     p);
    element_init_GT(sig->alpha, p);
    element_init_G1(sig->beta,  p);
    element_init_G1(sig->gamma, p);
    element_init_G1(sig->C1,    p);
    element_init_G1(sig->C2,    p);
}

// domain-separated transcript hash: h = H(VTM || TS || U || C1 || C2)
static void hash_transcript(element_t hout, pairing_t p,
                            element_t U, element_t C1, element_t C2,
                            const char *vtm, const char *ts){
    int lu = element_length_in_bytes(U);
    int l1 = element_length_in_bytes(C1);
    int l2 = element_length_in_bytes(C2);
    int lm = (int)strlen(vtm), lt = (int)strlen(ts);
    int total = 1+lu + 1+l1 + 1+l2 + 1+lm + 1+lt;
    unsigned char *buf = (unsigned char*)malloc(total), *cur = buf;
    *cur++ = 0xF0; element_to_bytes(cur, U);  cur += lu;
    *cur++ = 0xF1; element_to_bytes(cur, C1); cur += l1;
    *cur++ = 0xF2; element_to_bytes(cur, C2); cur += l2;
    *cur++ = 0xA0; memcpy(cur, vtm, lm);      cur += lm;
    *cur++ = 0xA1; memcpy(cur, ts,  lt);      cur += lt;
    element_from_hash(hout, buf, total);
    free(buf);
}

/*------------------ sign / verify ------------------*/
static void sign(sig_t *sig, sys_t *S, const veh_keys_t *K,
                 const char *vtm, const char *ts){
    element_t u, r, uh, h, h2, per1, t1, t2;
    element_init_Zr(u,  S->pairing);
    element_init_Zr(r,  S->pairing);
    element_init_Zr(uh, S->pairing);
    element_init_Zr(h,  S->pairing);
    element_init_Zr(h2, S->pairing);
    element_init_G1(per1, S->pairing);
    element_init_G1(t1,   S->pairing);
    element_init_G1(t2,   S->pairing);

    element_random(u);
    element_mul_zn(sig->U, S->P, u);       // U = uP

    // trace token (RC-only open)
    element_random(r);
    element_mul_zn(sig->C1, S->P, r);      // C1 = rP
    element_mul_zn(sig->C2, S->Q, r);      // rQ
    element_add(sig->C2, sig->C2, K->AID); // C2 = AID + rQ

    // h = H(VTM||TS||U||C1||C2)
    hash_transcript(h, S->pairing, sig->U, sig->C1, sig->C2, vtm, ts);

    // alpha = g^(u*h)
    element_mul(uh, u, h);
    element_pow_zn(sig->alpha, S->g, uh);

    // beta = (u*h)P + (h^2)*(u*PK)
    element_mul_zn(t1, S->P, uh);          // (u*h)P
    element_mul_zn(per1, K->PK, u);        // u*PK
    element_mul(h2, h, h);                 // h^2
    element_mul_zn(t2, per1, h2);          // (h^2)*(u*PK)
    element_add(sig->beta, t1, t2);

    // gamma = (u*h)*SK
    element_mul_zn(sig->gamma, K->SK, uh);

    element_clear(u); element_clear(r); element_clear(uh);
    element_clear(h); element_clear(h2); element_clear(per1);
    element_clear(t1); element_clear(t2);
}

static int verify_single(const sys_t *S, const sig_t *sig,
                         const char *vtm, const char *ts){
    element_t h, hQ, lhs, rhs, pair2;
    element_init_Zr(h,   S->pairing);
    element_init_G1(hQ,  S->pairing);
    element_init_GT(lhs, S->pairing);
    element_init_GT(rhs, S->pairing);
    element_init_GT(pair2,S->pairing);

    hash_transcript(h, S->pairing, sig->U, sig->C1, sig->C2, vtm, ts);
    element_mul_zn(hQ, S->Q, h);                // hQ

    element_pairing(lhs, sig->beta, S->P);      // e(beta,P)
    element_pairing(pair2, sig->gamma, hQ);     // e(gamma,hQ)
    element_mul(rhs, sig->alpha, pair2);        // alpha * e(gamma,hQ)

    int ok = (element_cmp(lhs, rhs) == 0);

    element_clear(h); element_clear(hQ);
    element_clear(lhs); element_clear(rhs); element_clear(pair2);
    return ok;
}

// Batch verification for n signatures.
// sigs[i] corresponds to (vtms[i], tss[i])
static int verify_batch(const sys_t *S, const sig_t *sigs,
                        const char **vtms, const char **tss, int n){
    element_t beta_sum, gamma_h_sum, prod_alpha;
    element_t lhs, rhs, pair_part;

    element_init_G1(beta_sum,    S->pairing);
    element_init_G1(gamma_h_sum, S->pairing);
    element_init_GT(prod_alpha,  S->pairing);
    element_init_GT(lhs,         S->pairing);
    element_init_GT(rhs,         S->pairing);
    element_init_GT(pair_part,   S->pairing);

    element_set0(beta_sum);               // additive identity in G1
    element_set0(gamma_h_sum);
    element_set1(prod_alpha);             // multiplicative identity in GT

    for(int i=0;i<n;i++){
        // sum beta
        element_add(beta_sum, beta_sum, sigs[i].beta);

        // gamma*h
        element_t h, term;
        element_init_Zr(h, S->pairing);
        element_init_G1(term, S->pairing);
        hash_transcript(h, S->pairing, sigs[i].U, sigs[i].C1, sigs[i].C2, vtms[i], tss[i]);
        element_mul_zn(term, sigs[i].gamma, h);          // gamma_i * h_i
        element_add(gamma_h_sum, gamma_h_sum, term);

        // prod alpha
        element_mul(prod_alpha, prod_alpha, sigs[i].alpha);

        element_clear(h); element_clear(term);
    }

    // Check: e(sum beta, P) ?= (prod alpha) * e(sum gamma*h, Q)
    element_pairing(lhs, beta_sum, S->P);
    element_pairing(pair_part, gamma_h_sum, S->Q);
    element_mul(rhs, prod_alpha, pair_part);

    int ok = (element_cmp(lhs, rhs) == 0);

    element_clear(beta_sum); element_clear(gamma_h_sum); element_clear(prod_alpha);
    element_clear(lhs); element_clear(rhs); element_clear(pair_part);
    return ok;
}

/*------------------ demo main ------------------*/
int main(int argc, char **argv){
    if(argc < 2){ fprintf(stderr,"Usage: %s a.param\n", argv[0]); return 1; }

    sys_t S; setup(&S, argv[1]);

    // 假設同一輛車簽兩則訊息（也可多車，程式一樣適用）
    veh_keys_t K; veh_keys_init(&K, S.pairing);
    veh_keygen(&K, &S, "VID-EXAMPLE-123");

    const char *m[3]  = {"VTM: speed=42","VTM: brake=1","VTM: temp=75"};
    const char *ts[3] = {"1700000001","1700000002","1700000003"};

    sig_t sigs[3];
    for(int i=0;i<3;i++){
        sig_init(&sigs[i], S.pairing);
        sign(&sigs[i], &S, &K, m[i], ts[i]);
    }

    printf("Single verify #1: %s\n", verify_single(&S, &sigs[0], m[0], ts[0]) ? "OK":"FAIL");
    printf("Single verify #2: %s\n", verify_single(&S, &sigs[1], m[1], ts[1]) ? "OK":"FAIL");
    printf("Single verify #3: %s\n", verify_single(&S, &sigs[2], m[2], ts[2]) ? "OK":"FAIL");

    printf("Batch verify (3): %s\n", verify_batch(&S, sigs, m, ts, 3) ? "OK":"FAIL");

    return 0;
}
