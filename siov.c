// src/siov.c
// IBE-style anonymous sign + RC-only trace token + Batch Verification
// Works on Ubuntu/WSL with libpbc & libgmp.
// Build: make        Run: ./bin/siov [options]
//
// Options:
//   --count N            產生/驗證 N 筆簽章 (default 3)
//   --message-size B     訊息大小 bytes (default 64)
//   --verify on|off      是否做單筆與批次驗證 (default on)
//   --trace  on|off      顯示中間變數與等式結果 (default off)
//   --rbits N --qbits M  PBC type-A 參數位元數 (default r=160, q=512)
//   --seed S             PRNG 種子 (default /dev/urandom)
// 說明：本程式在 runtime 以 pbc_param_init_a_gen 產生 pairing，無需 a.param 檔。

#include <pbc/pbc.h>
#include <gmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

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

static void die(const char *m){ fprintf(stderr, "[ERR] %s\n", m); exit(1); }

/* ---------------- Pairing setup (Type A, generated at runtime) ---------------- */
static void setup(sys_t *S, int rbits, int qbits){
    pbc_param_t par;
    pbc_param_init_a_gen(par, rbits, qbits);              // 例：r=160, q=512
    pairing_init_pbc_param(S->pairing, par);
    pbc_param_clear(par);

    element_init_G1(S->P, S->pairing);
    element_init_G1(S->Q, S->pairing);
    element_init_GT(S->g, S->pairing);
    element_init_Zr(S->x, S->pairing);
    element_init_Zr(S->s, S->pairing);

    element_random(S->P);
    element_pairing(S->g, S->P, S->P);
    element_random(S->x);
    element_random(S->s);
    element_mul_zn(S->Q, S->P, S->x);                    // Q = xP
}

/* ---------------- Vehicle key generation ---------------- */
static void veh_keys_init(veh_keys_t *K, pairing_t p){
    element_init_G1(K->AID, p);
    element_init_G1(K->SK,  p);
    element_init_G1(K->PK,  p);
}
static void veh_keygen(veh_keys_t *K, sys_t *S, const unsigned char *VID, size_t vlen){
    element_from_hash(K->AID, VID, vlen);                // AID = f(VID)
    element_mul_zn(K->SK, K->AID, S->s);                 // SK = s*AID
    element_mul_zn(K->PK, K->SK, S->x);                  // PK = x*SK
}

/* ---------------- Transcript hash: h = H(VTM || TS || U || C1 || C2) ---------------- */
static void hash_transcript(element_t hout, pairing_t p,
                            element_t U, element_t C1, element_t C2,
                            const unsigned char *m, size_t mlen,
                            const unsigned char *ts, size_t tslen){
    int lu = element_length_in_bytes(U);
    int l1 = element_length_in_bytes(C1);
    int l2 = element_length_in_bytes(C2);
    size_t total = 1+lu + 1+l1 + 1+l2 + 1+mlen + 1+tslen;
    unsigned char *buf = (unsigned char*)malloc(total), *cur = buf;
    *cur++ = 0xF0; element_to_bytes(cur, U);  cur += lu;
    *cur++ = 0xF1; element_to_bytes(cur, C1); cur += l1;
    *cur++ = 0xF2; element_to_bytes(cur, C2); cur += l2;
    *cur++ = 0xA0; memcpy(cur, m,  mlen);     cur += mlen;
    *cur++ = 0xA1; memcpy(cur, ts, tslen);    cur += tslen;
    element_from_hash(hout, buf, total);
    free(buf);
}

/* ---------------- Sign / Verify / Batch / RC-trace verify ---------------- */
static void sig_init(sig_t *sig, pairing_t p){
    element_init_G1(sig->U,     p);
    element_init_GT(sig->alpha, p);
    element_init_G1(sig->beta,  p);
    element_init_G1(sig->gamma, p);
    element_init_G1(sig->C1,    p);
    element_init_G1(sig->C2,    p);
}
static void sig_clear(sig_t *sig){
    element_clear(sig->U); element_clear(sig->alpha); element_clear(sig->beta);
    element_clear(sig->gamma); element_clear(sig->C1); element_clear(sig->C2);
}

static void sign_once(sig_t *sig, sys_t *S, const veh_keys_t *K,
                      const unsigned char *msg, size_t mlen,
                      const unsigned char *ts,  size_t tslen){
    element_t u, r, uh, h, h2, per1, t1, t2;
    element_init_Zr(u,  S->pairing);
    element_init_Zr(r,  S->pairing);
    element_init_Zr(uh, S->pairing);
    element_init_Zr(h,  S->pairing);
    element_init_Zr(h2, S->pairing);
    element_init_G1(per1, S->pairing);
    element_init_G1(t1,   S->pairing);
    element_init_G1(t2,   S->pairing);

    element_random(u);                                    // u
    element_mul_zn(sig->U, S->P, u);                      // U = uP

    element_random(r);                                    // trace token τ
    element_mul_zn(sig->C1, S->P, r);                     // C1 = rP
    element_mul_zn(sig->C2, S->Q, r);                     // rQ
    element_add(sig->C2, sig->C2, K->AID);                // C2 = AID + rQ

    hash_transcript(h, S->pairing, sig->U, sig->C1, sig->C2, msg, mlen, ts, tslen);

    element_mul(uh, u, h);                                // uh
    element_pow_zn(sig->alpha, S->g, uh);                 // α = g^(u*h)

    element_mul_zn(t1, S->P, uh);                         // (u*h)P
    element_mul_zn(per1, K->PK, u);                       // u*PK
    element_mul(h2, h, h);                                // h^2
    element_mul_zn(t2, per1, h2);                         // (h^2)*(u*PK)
    element_add(sig->beta, t1, t2);                       // β

    element_mul_zn(sig->gamma, K->SK, uh);                // γ

    element_clear(u); element_clear(r); element_clear(uh);
    element_clear(h); element_clear(h2); element_clear(per1);
    element_clear(t1); element_clear(t2);
}

static int verify_single(const sys_t *S, const sig_t *sig,
                         const unsigned char *msg, size_t mlen,
                         const unsigned char *ts,  size_t tslen,
                         int trace){
    element_t h, hQ, lhs, rhs, pair2;
    element_init_Zr(h,   S->pairing);
    element_init_G1(hQ,  S->pairing);
    element_init_GT(lhs, S->pairing);
    element_init_GT(rhs, S->pairing);
    element_init_GT(pair2,S->pairing);

    hash_transcript(h, S->pairing, sig->U, sig->C1, sig->C2, msg, mlen, ts, tslen);
    element_mul_zn(hQ, S->Q, h);                           // hQ

    element_pairing(lhs, sig->beta, S->P);                 // e(β,P)
    element_pairing(pair2, sig->gamma, hQ);                // e(γ,hQ)
    element_mul(rhs, sig->alpha, pair2);                   // α * e(γ,hQ)

    int ok = (element_cmp(lhs, rhs) == 0);
    if(trace){
        printf("[TRACE] single verify: %s\n", ok ? "OK" : "FAIL");
        if(!ok){
            printf("lhs != rhs; equality failed.\n");
        }
    }
    element_clear(h); element_clear(hQ);
    element_clear(lhs); element_clear(rhs); element_clear(pair2);
    return ok;
}

static int verify_batch(const sys_t *S, const sig_t *sigs,
                        const unsigned char **msgs, size_t *mlens,
                        const unsigned char **tss,  size_t *tslens,
                        int n, int trace){
    element_t beta_sum, gamma_h_sum, prod_alpha;
    element_t lhs, rhs, pair_part;

    element_init_G1(beta_sum,    S->pairing);
    element_init_G1(gamma_h_sum, S->pairing);
    element_init_GT(prod_alpha,  S->pairing);
    element_init_GT(lhs,         S->pairing);
    element_init_GT(rhs,         S->pairing);
    element_init_GT(pair_part,   S->pairing);

    element_set0(beta_sum);
    element_set0(gamma_h_sum);
    element_set1(prod_alpha);

    for(int i=0;i<n;i++){
        element_add(beta_sum, beta_sum, sigs[i].beta);     // Σβ
        element_mul(prod_alpha, prod_alpha, sigs[i].alpha);// ∏α

        element_t h, term;
        element_init_Zr(h, S->pairing);
        element_init_G1(term, S->pairing);
        hash_transcript(h, S->pairing, sigs[i].U, sigs[i].C1, sigs[i].C2,
                        msgs[i], mlens[i], tss[i], tslens[i]);
        element_mul_zn(term, sigs[i].gamma, h);            // γ*h
        element_add(gamma_h_sum, gamma_h_sum, term);       // Σ(γ*h)
        element_clear(h); element_clear(term);
    }

    element_pairing(lhs, beta_sum, S->P);
    element_pairing(pair_part, gamma_h_sum, S->Q);
    element_mul(rhs, prod_alpha, pair_part);

    int ok = (element_cmp(lhs, rhs) == 0);
    if(trace){
        printf("[TRACE] batch verify (%d): %s\n", n, ok ? "OK" : "FAIL");
        if(!ok) printf("lhs != rhs in batch equality\n");
    }
    element_clear(beta_sum); element_clear(gamma_h_sum); element_clear(prod_alpha);
    element_clear(lhs); element_clear(rhs); element_clear(pair_part);
    return ok;
}

/* RC-only verifiable opening: e(γ,P) ?= e(SK, U)^h  */
static int rc_trace_verify(const sys_t *S, const sig_t *sig,
                           const unsigned char *msg, size_t mlen,
                           const unsigned char *ts,  size_t tslen,
                           int trace){
    element_t AID, SK, h, lhs, rhs, e1, xC1;
    element_init_G1(AID, S->pairing);
    element_init_G1(SK,  S->pairing);
    element_init_Zr(h,   S->pairing);
    element_init_GT(lhs, S->pairing);
    element_init_GT(rhs, S->pairing);
    element_init_GT(e1,  S->pairing);
    element_init_G1(xC1, S->pairing);

    element_mul_zn(xC1, sig->C1, S->x);                     // x*C1
    element_sub(AID, sig->C2, xC1);                         // AID = C2 - xC1
    element_mul_zn(SK,  AID, S->s);                         // SK = s*AID
    hash_transcript(h, S->pairing, sig->U, sig->C1, sig->C2, msg, mlen, ts, tslen);

    element_pairing(lhs, sig->gamma, S->P);                 // e(γ,P)
    element_pairing(e1,  SK, sig->U);                       // e(SK, U)
    element_pow_zn(rhs, e1, h);                             // e(SK,U)^h

    int ok = (element_cmp(lhs, rhs) == 0);
    if(trace){
        printf("[TRACE] RC open+verify: %s\n", ok ? "OK" : "FAIL");
    }
    element_clear(AID); element_clear(SK); element_clear(h); element_clear(lhs);
    element_clear(rhs); element_clear(e1); element_clear(xC1);
    return ok;
}

/* ---------------- util: random buffer ---------------- */
static void fill_random(unsigned char *buf, size_t len, unsigned int seed){
    FILE *fp = fopen("/dev/urandom","rb");
    if(fp){ fread(buf,1,len,fp); fclose(fp); return; }
    srand(seed ? seed : (unsigned)time(NULL));
    for(size_t i=0;i<len;i++) buf[i] = (unsigned char)(rand() & 0xFF);
}

/* ---------------- CLI ---------------- */
static int eq(const char *a, const char *b){ return strcmp(a,b)==0; }

int main(int argc, char **argv){
    int count=3, msg_size=64, verify=1, trace=0, rbits=160, qbits=512;
    unsigned int seed = 0;

    for(int i=1;i<argc;i++){
        if(eq(argv[i],"--count") && i+1<argc)       count = atoi(argv[++i]);
        else if(eq(argv[i],"--message-size")&&i+1<argc) msg_size=atoi(argv[++i]);
        else if(eq(argv[i],"--verify") && i+1<argc) verify = eq(argv[++i],"on");
        else if(eq(argv[i],"--trace")  && i+1<argc) trace  = eq(argv[++i],"on");
        else if(eq(argv[i],"--rbits")  && i+1<argc) rbits  = atoi(argv[++i]);
        else if(eq(argv[i],"--qbits")  && i+1<argc) qbits  = atoi(argv[++i]);
        else if(eq(argv[i],"--seed")   && i+1<argc) seed   = (unsigned)atoi(argv[++i]);
        else if(eq(argv[i],"--help")){
            printf("Usage: %s [--count N] [--message-size B] [--verify on|off] [--trace on|off] [--rbits N] [--qbits M] [--seed S]\n", argv[0]);
            return 0;
        }
    }

    sys_t S; setup(&S, rbits, qbits);
    veh_keys_t K; veh_keys_init(&K, S.pairing);
    const char *VID = "VID-DEMO-001";
    veh_keygen(&K, &S, (const unsigned char*)VID, strlen(VID));

    // prepare messages & timestamps
    sig_t *sigs = (sig_t*)calloc(count, sizeof(sig_t));
    unsigned char **msgs = (unsigned char**)calloc(count, sizeof(unsigned char*));
    size_t *mlens = (size_t*)calloc(count, sizeof(size_t));
    unsigned char **tss  = (unsigned char**)calloc(count, sizeof(unsigned char*));
    size_t *tslens = (size_t*)calloc(count, sizeof(size_t));

    for(int i=0;i<count;i++){
        sig_init(&sigs[i], S.pairing);
        msgs[i]  = (unsigned char*)malloc(msg_size);
        mlens[i] = msg_size;
        fill_random(msgs[i], msg_size, seed + i + 1);

        char tsbuf[32]; snprintf(tsbuf,sizeof(tsbuf), "%u", (unsigned)(1700000000 + i));
        tslens[i] = strlen(tsbuf);
        tss[i] = (unsigned char*)malloc(tslens[i]);
        memcpy(tss[i], tsbuf, tslens[i]);

        sign_once(&sigs[i], &S, &K, msgs[i], mlens[i], tss[i], tslens[i]);

        if(trace){
            printf("[TRACE] ---- Signature #%d ----\n", i+1);
            element_printf("U   = %B\n", sigs[i].U);
            element_printf("alpha(GT) = %B\n", sigs[i].alpha);
            element_printf("beta(G1)  = %B\n", sigs[i].beta);
            element_printf("gamma(G1) = %B\n", sigs[i].gamma);
            element_printf("C1  = %B\n", sigs[i].C1);
            element_printf("C2  = %B\n", sigs[i].C2);
        }
    }

    if(verify){
        int all_ok = 1;
        for(int i=0;i<count;i++){
            int ok1 = verify_single(&S, &sigs[i], msgs[i], mlens[i], tss[i], tslens[i], trace);
            int ok2 = rc_trace_verify(&S, &sigs[i], msgs[i], mlens[i], tss[i], tslens[i], trace);
            all_ok &= ok1 && ok2;
        }
        int okb = verify_batch(&S, sigs, (const unsigned char**)msgs, mlens,
                               (const unsigned char**)tss, tslens, count, trace);
        printf("Single-verify(all): %s, Batch-verify: %s\n",
               all_ok? "OK":"FAIL", okb? "OK":"FAIL");
    }else{
        printf("Verify skipped (--verify off)\n");
    }

    for(int i=0;i<count;i++){
        sig_clear(&sigs[i]); free(msgs[i]); free(tss[i]);
    }
    free(sigs); free(msgs); free(mlens); free(tss); free(tslens);
    return 0;
}
