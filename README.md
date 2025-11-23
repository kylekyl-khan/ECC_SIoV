# SIOV with MIRACL Core (C)

This is a clean, MIRACL Core-based skeleton for the SIOV identity-based encryption and pairing-based signature demo.
It targets Ubuntu/WSL with a simple Makefile build and a minimal CLI.

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
./bin/siov --count 50 --verify on --trace off
./bin/siov --count 10 --verify on --trace on
python3 scripts/benchmark.py --repeat 10 --count 100
```

## Curve choice
This skeleton uses the BN254 pairing-friendly curve from MIRACL Core. The types in `siov_miracl.c` wrap `ECP_BN254`, `ECP2_BN254`, `FP12_BN254`, and `BIG_256_56`.

## Directory layout
- `include/` high level headers
- `src/` implementation (CLI, MIRACL glue, SIOV logic, tracing)
- `scripts/benchmark.py` quick CSV timing harness
- `third_party/miracl-core/` external dependency (not vendored)

## Notes
The cryptographic equations are kept intentionally simple for clarity and compile-time friendliness. The tracing module prints the pairings used during verification when enabled, and batch verification currently performs naive per-signature checks as a placeholder for future aggregation strategies.
