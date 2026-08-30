# RESUME — experiment/oqs-minimal-size

Handoff note so a fresh session can finish this experiment without re-deriving
context. This branch is a **local experiment** (size + interop + benchmark of
this provider vs oqs-provider); it is not part of the shipped provider.

## Where things stand (2026-08-30)

Merged to `main` already (done, green CI):
- **Native-backend fix** (PR #1): x86_64 native build now actually engages the
  AVX2 backend (`-mavx2 -mbmi2` on the mldsa-native amalgamation + asm). Before
  the fix the module shipped portable C despite advertising "native asm" and was
  ~4× slower. AArch64 was already fine (NEON baseline).
- **Nightly regression guard** (PR #2): `.github/workflows/bench-regression.yml`
  + `ci/bench_regression.c` + `ci/bench_vs_oqs.sh`. Fails (and opens/auto-closes a
  per-arch `perf-regression` issue) if this provider is >1.5× slower than
  oqs-provider on keygen/sign. This branch has both (merged in).

Done on this branch:
- **Consolidated the two interop programs into one** table-driven `interop.c`
  (two libctxs = two parties; RAW-parameter transport for plain ML-DSA, SPKI-DER
  for hybrids; `--benchmark` times sign/verify each side). Deleted
  `oqs_vs_mldsanative_interop.c` and `hybrid_interop.c`. `run.sh` step 6 now
  builds/runs the single `interop.c --benchmark`.

## Status: COMPLETE (2026-08-30)

All three TODO items below are done. `RESULTS.md` is refreshed against a
native-backend build and rewritten self-contained; the ⚠️ banner is gone.

1. **Numbers refreshed** against a native-backend (`x86_64 AVX2`) build.
   Re-run any time with:
   ```sh
   HP=/home/mib/git/baentsch/hybrid-provider          # sibling checkouts
   cmake -S . -B build-34 \
     -DOPENSSL_CRYPTO_LIBRARY=$HP/.local-34/lib64/libcrypto.so \
     -DOPENSSL_SSL_LIBRARY=$HP/.local-34/lib64/libssl.so \
     -DOPENSSL_INCLUDE_DIR=$HP/.local-34/include \
     -DOPENSSL_LIB_DIR=$HP/.local-34/lib64
   cmake --build build-34 --target mldsanative       # reports "native (x86_64 asm)"
   bash experiments/oqs-minimal-size/run.sh
   ```
   Measured this run (x86_64, `.local-34` = OpenSSL 3.4.2):
   - `mldsanative.so` stripped = **211.1 KiB** (216184 B) — native AVX2.
     `oqsprovider.so` = 523.9 KiB, `hybrid.so` = 99.3 KiB.
   - Equivalent-functionality stack: 211.1+99.3 = 310.5 KiB vs 523.9 KiB → **1.69×**.
     Plain ML-DSA: 211.1 vs 494.9 KiB → **2.3×**.
   - Speed: at **parity or slightly ahead** of oqs-provider in `interop.c
     --benchmark` (both wrap the same mldsa-native AVX2 core). That path is
     init-dominated; for a crypto-level number cite `ci/bench_regression.c` (the
     nightly guard bounds ours within 1.5× of oqs).

2. **`RESULTS.md` rewritten self-contained** — no "earlier/now/grew from"
   framing; every result a standalone fact with its proof point; ⚠️ banner removed.

3. **Interop re-verified** after the native rebuild: 6/6 plain + 8/8 hybrid,
   ALL INTEROP PASSED; `--benchmark` table populated.

## Keeping the branch current / pushing

The remote branch was updated by **merging** `main` in (not rebasing) to avoid a
force-push, which repo policy blocks. To refresh again: `git merge --no-edit main`.
The diff vs `main` should stay limited to `experiments/oqs-minimal-size/`.

## Key paths
- OpenSSL <3.5 (oqs serves ML-DSA there): `HP/.local-34` (3.4.2); a clean 3.4 is
  also at `/tmp/ossl34` if it survived. OpenSSL 3.5: `HP/.local`.
- liboqs / oqs-provider / hybrid-provider source: under `HP/`.
- `run.sh` defaults `OURS_SO` to `build-34/mldsanative.so` — must be a native build.
