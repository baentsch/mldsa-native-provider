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

## What still needs doing (the actual TODO)

1. **Refresh all numbers in `RESULTS.md`** against a provider built *with the
   native backend* (the current figures were taken pre-fix, portable C). Steps:
   ```sh
   HP=/home/mib/git/baentsch/hybrid-provider          # sibling checkouts
   # a) build THIS provider with the native backend (AUTO gives native on x86_64):
   cmake -S . -B build-34 \
     -DOPENSSL_CRYPTO_LIBRARY=$HP/.local-34/lib64/libcrypto.so \
     -DOPENSSL_SSL_LIBRARY=$HP/.local-34/lib64/libssl.so \
     -DOPENSSL_INCLUDE_DIR=$HP/.local-34/include \
     -DOPENSSL_LIB_DIR=$HP/.local-34/lib64
   cmake --build build-34 --target mldsanative       # must report "native (x86_64 asm)"
   # b) re-run the experiment (builds minimal liboqs + oqsprovider + hybrid):
   bash experiments/oqs-minimal-size/run.sh
   ```
   Known deltas to apply (measured this session, x86_64, `.local-34` = OpenSSL 3.4):
   - `mldsanative.so` stripped size: **~167 KiB → ~211 KiB** (real AVX2 code).
     The 3.0×/1.97× ratios in RESULTS shrink accordingly — recompute from run.sh
     output (oqsprovider ~524 KiB and hybrid ~99 KiB are unchanged).
   - Speed vs oqs-provider: now **~parity** (both wrap the same mldsa-native AVX2
     core). The guard's crypto-level measure showed ours 0.74–0.91× of oqs.
   - vs the OpenSSL 3.5 **default** provider (portable C), `openssl speed`:
     ML-DSA-65 keygen ~4.3×, sign ~9.0×, verify ~4.6× (already in README).
   - Note `interop.c --benchmark` times *full* one-shot sign (includes EVP init),
     so it is init-dominated and understates the crypto gap; for a crypto-level
     ours-vs-oqs number use `ci/bench_regression.c` (reused ctx). Consider making
     `interop.c`'s bench reuse the ctx too, or just cite the guard's numbers.

2. **Rewrite `RESULTS.md` to be self-contained** (the other standing request):
   remove phrasings that only make sense to someone who watched the sessions
   ("the earlier gap", "now at parity", "grew from X"), state every result as a
   standalone fact with its proof point, keep all findings. Drop the ⚠️ banner
   once the numbers are refreshed.

3. **Re-verify interop still passes** after the rebuild: `run.sh` prints 6/6
   plain + 8/8 hybrid; `--benchmark` prints the per-level table.

## Keeping the branch current / pushing

The remote branch was updated by **merging** `main` in (not rebasing) to avoid a
force-push, which repo policy blocks. To refresh again: `git merge --no-edit main`.
The diff vs `main` should stay limited to `experiments/oqs-minimal-size/`.

## Key paths
- OpenSSL <3.5 (oqs serves ML-DSA there): `HP/.local-34` (3.4.2); a clean 3.4 is
  also at `/tmp/ossl34` if it survived. OpenSSL 3.5: `HP/.local`.
- liboqs / oqs-provider / hybrid-provider source: under `HP/`.
- `run.sh` defaults `OURS_SO` to `build-34/mldsanative.so` — must be a native build.
