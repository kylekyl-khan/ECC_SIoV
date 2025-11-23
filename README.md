# SIOV with MIRACL Core (C)

This repository contains a MIRACL Core-based SIOV-inspired identity-based / pairing-based signature demo for BN254. It targets Ubuntu/WSL with a simple Makefile build, a minimal CLI, tracing, and batch verification support.

## Dependencies
- Ubuntu 22.04 (WSL works)
- `gcc` or `clang`
- Python 3 (for the benchmark helper)
- MIRACL Core C sources placed under `third_party/miracl-core` (clone https://github.com/miracl/core)

Clone with submodule (recommended):
```bash
git clone https://github.com/miracl/core third_party/miracl-core
```

Then build MIRACL Core C (see MIRACL documentation). The Makefile expects the static library at `third_party/miracl-core/c/lib/libcore.a` and headers in `third_party/miracl-core/c/include`.

## Building
```bash
make
```

Example runs:
```bash
# single signatures without trace
./bin/siov --count 50 --verify on --trace off

# trace the first signature's pairing equation
./bin/siov --count 3 --verify on --trace on

# batch verification mode
./bin/siov --count 50 --verify on --trace off --batch on

# benchmark helper
python3 scripts/benchmark.py --repeat 10 --count 100
```

## Protocol overview

The demo implements a bilinear pairing-based signature flow reminiscent of SIOV, using MIRACL Core's BN254 curve with pairing \( e : G_1 \times G_2 \to G_T \).

**Setup**

- Sample master secret \( s \in \mathbb{Z}_q^* \).
- Pick generators \( P \in G_1 \), \( P_2 \in G_2 \).
- Derive public parameters:
  - \( Q = s P \in G_1 \)
  - \( Q_2 = s P_2 \in G_2 \)
  - \( g = e(P, P_2) \in G_T \)

**Vehicle key generation (VAD)**

Given an anonymous identity string `VAD`:

- \( h_{\text{vad}} = H_{\text{vad}}(\text{VAD}) \in \mathbb{Z}_q \)
- \( \text{PK} = h_{\text{vad}} P \in G_1 \)
- \( \text{PK}_2 = h_{\text{vad}} P_2 \in G_2 \)
- \( \text{SK} = s \cdot \text{PK} \in G_1 \)

**Signing traffic data**

For a traffic data payload `TD` (the demo hashes `msg || ts`):

1. Sample \( r, k, t \leftarrow_R \mathbb{Z}_q^* \).
2. \( \sigma_1 = g^r \in G_T \).
3. \( \text{PPr\_AD1} = r \cdot \text{SK} \in G_1 \).
4. \( \text{PPr\_AD2} = r t \cdot \text{PK} \in G_1 \).
5. \( h_{\text{td}} = H_{\text{td}}(\text{TD}) \in \mathbb{Z}_q \).
6. \( \sigma_2 = (r k) P + (t h_{\text{td}}) \cdot \text{PPr\_AD1} \in G_1 \).
7. \( \sigma_3 = \text{PPr\_AD2} \in G_1 \).

The signature is \( \sigma = (\sigma_1, \sigma_2, \sigma_3) \).

**Verification**

- Compute \( h_{\text{td}} = H_{\text{td}}(\text{TD}) \) and \( Q_2^h = h_{\text{td}} Q_2 \in G_2 \).
- Check the pairing equation

\[
e(\sigma_2, P_2) \stackrel{?}{=} \sigma_1 \cdot e(\sigma_3, Q_2^h).
\]

**Batch verification (random linear combination)**

For signatures \( \{\sigma_i\}_{i=1}^n \) on messages \( TD_i \):

1. For each \( i \), sample \( \beta_i \leftarrow_R \mathbb{Z}_q^* \) and compute \( h_i = H_{\text{td}}(TD_i) \).
2. Aggregate:
   - \( S_2 = \sum_i \beta_i \sigma_{2,i} \in G_1 \)
   - \( S_3 = \sum_i \beta_i h_i \sigma_{3,i} \in G_1 \)
   - \( G_\beta = \prod_i \sigma_{1,i}^{\beta_i} \in G_T \)
3. Verify

\[
e(S_2, P_2) \stackrel{?}{=} G_\beta \cdot e(S_3, Q_2).
\]

This randomized batch check reduces the number of pairings versus naive per-signature verification.

## Implementation details

- `src/siov_miracl.c` wraps MIRACL Core BN254 types (`ECP_BN254`, `ECP2_BN254`, `FP12_BN254`, `BIG_256_56`) behind simple scalar/G1/G2/GT helpers, including hashing to scalars, scalar multiplication, addition, pairing, exponentiation in GT, and identity setters for aggregation.
- `src/siov.c` implements the full setup, key generation, signing, verification, and randomized batch verification logic described above. Hashes are computed with SHA-256 reduced mod the curve order via `siov_hash_to_scalar`.
- `src/siov_trace.c` prints the pairing equation inputs and outputs when `--trace on` is supplied, showing `h_td`, `sigma1`, `sigma2`, `sigma3`, the scaled `Q2`, and both sides of the verification equation.
- `src/main.c` wires the CLI flags (`--count`, `--verify`, `--trace`, `--batch`), performs setup and a demo vehicle key extraction, signs `count` synthetic messages, verifies individually, and optionally batch-verifies. Timing is measured with `clock_gettime` and reported for signing and verification.
- `scripts/benchmark.py` repeatedly runs the binary, parses the reported verification time, and emits a CSV plus min/avg/max statistics.

## Curve choice

The implementation targets MIRACL Core's BN254 curve. The wrappers in `siov_miracl.c` serialize/deserialize curve objects internally and expose fixed-size structs suitable for copying and tracing.

## Directory layout

- `include/` high level headers
- `src/` implementation (CLI, MIRACL glue, SIOV logic, tracing)
- `scripts/benchmark.py` quick CSV timing harness
- `third_party/miracl-core/` external dependency (not vendored)

## Security disclaimer

This code is a research/educational demo. It has not been audited, is not hardened for side-channel resistance, and should not be used in production or to protect real-world secrets.
