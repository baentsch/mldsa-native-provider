# Experiment: minimal oqs-provider vs mldsa-native-provider (binary size + interop)

**Status:** a size/speed/interop study, merged to `main` under
`experiments/oqs-minimal-size/`. It is a standalone comparison, **not** part of
the shipped provider runtime or build. All numbers are x86_64, `strip -s`,
self-contained modules (crypto statically linked), gcc `-O3`/Release.
`mldsanative.so` is built with its native backend (x86_64 AVX2 asm), matching the
mldsa-native core that liboqs — and therefore oqs-provider — also compiles.
Reproduce with `run.sh` (see the bottom of this file).

## Head-to-head summary (TL;DR)

For the same ML-DSA functionality, this provider is **both smaller and faster**
than a minimal oqs-provider. Two things to keep straight when reading every table
below:

- **Size** is a stripped module in KiB — **smaller is better** (↓).
- **Speed** is *throughput* in **k ops/s = thousands of operations per second** —
  **bigger is better** (↑). `30.6` means 30,600 operations every second; a larger
  number finishes more work per second, i.e. is faster. (As time-per-op that is
  1/30600 s ≈ 33 µs; the reciprocal, where smaller would be better — but the
  tables are all throughput.)

**Plain ML-DSA** — `mldsanative.so` vs `oqsprovider.so`, level ML-DSA-65 (mid):

| plain ML-DSA-65 | this provider | oqs-provider | this provider is |
|---|--:|--:|:--|
| module size, stripped (↓ better) | **211.1 KiB** | 494.9 KiB | **2.3× smaller** |
| keygen, k ops/s (↑ better) | **30.6** | 23.8 | **1.29× faster** |
| sign, k ops/s (↑ better) | **11.2** | 9.6 | **1.17× faster** |
| verify, k ops/s (↑ better) | **31.4** | 24.3 | **1.29× faster** |

Across all three levels: **2.3× smaller** and **1.12–1.34× faster** on keygen /
sign / verify. In every speed row the bigger number is on this provider's side.

**ML-DSA + the 4 ML-DSA hybrids** — functionally equivalent stacks:

| equivalent-functionality stack | Side B: this + hybrid-provider | Side A: oqs-provider | Side B is |
|---|--:|--:|:--|
| total module size, stripped (↓ better) | **310.5 KiB** (211.1 + 99.3) | 523.9 KiB | **1.69× smaller** |
| plain-ML-DSA speed | 1.12–1.34× faster | baseline | **faster** |
| hybrid speed | ≈ parity (within ~10%) | baseline | ~equal |

(keygen ratios from `ci/bench_regression.c`; sign/verify from `interop.c`; both
reused-context. Per-level detail and the one-shot-vs-reused breakdown follow.)

## Goal

An apples-to-apples comparison of the code that must ship to deliver the same
ML-DSA functionality two ways:

- **Side A — oqs-provider**, built against a *minimal* liboqs (ML-DSA only), with
  its `generate.yml` reduced so it serves exactly ML-DSA + the four ML-DSA
  concatenation hybrids.
- **Side B — this provider + hybrid-provider**: `mldsanative.so` delivers
  ML-DSA; `hybrid-provider` (tables trimmed to the same four hybrids) delivers
  the hybrids, sourcing its ML-DSA component **from mldsanative**.

...and to confirm the two stacks interoperate.

## How the minimal builds were made

- **liboqs** (static, host-optimized, no OpenSSL dep):
  `-DOQS_MINIMAL_BUILD="SIG_ml_dsa_44;SIG_ml_dsa_65;SIG_ml_dsa_87"
   -DBUILD_SHARED_LIBS=OFF -DOQS_DIST_BUILD=OFF -DOQS_USE_OPENSSL=OFF
   -DOQS_BUILD_ONLY_LIB=ON` → `liboqs.a` ≈ 1.1 MiB (only ML-DSA objects are
  pulled into the provider .so at link time).
- **oqs-provider**: `generate.yml` edited to `kems: []` and `sigs:` = the ML-DSA
  family only, then `python3 oqs-template/generate.py`, then built against the
  minimal liboqs (static-linked into `oqsprovider.so`).
- **hybrid-provider**: built with `-DHYBRID_COMPOSITE=OFF` (the option defaults
  to ON) so `hybrid.so` carries only the concatenation hybrids that oqs-provider
  also serves — an apples-to-apples size baseline. Its X-macro tables
  (`HYBRID_SIG_LIST`/`HYBRID_KEM_LIST` in `hybrid_prov.h`) were trimmed to the
  four ML-DSA hybrids and no KEM hybrids.

## Binary sizes (stripped)

### Pure ML-DSA only

| module | size | vs ours |
|---|--:|--:|
| `mldsanative.so` (this provider) | **211.1 KiB** | 1.0× |
| `oqsprovider.so`, regenerated ML-DSA-only | 494.9 KiB | 2.3× |
| `oqsprovider.so`, minimal liboqs but **tables not regenerated** | 1195.6 KiB | 5.7× |

`mldsanative.so` is 211.1 KiB (216184 B stripped). It includes both the native
AVX2 ML-DSA core and the OpenSSL < 3.5 parity features (TLS-SIGALG capability,
OID/sigid registration, cipher-aware/text encoders, and the manual SPKI
decoder). It is the smallest module by a wide margin.

The last two rows show why `generate.yml` regeneration matters. Building
oqs-provider against a minimal ML-DSA-only liboqs *without* regenerating its
tables still advertises ~90 algorithms and links to 1195.6 KiB; all non-ML-DSA
algorithms are **non-functional** (`genpkey falcon512` → "Could not create OQS
signature algorithm Falcon-512. Enabled in liboqs?"). Regenerating the tables to
ML-DSA-only removes them and drops the module to 494.9 KiB.

Enabling the four ML-DSA hybrids in oqs-provider adds only +29 KiB
(494.9 → 523.9 KiB): the hybrid-composition code is already compiled in, so
hybrids are essentially table entries.

### Functionally equivalent stacks: ML-DSA + the 4 ML-DSA hybrids

| stack | modules | size | ratio |
|---|---|--:|--:|
| **Side A** oqs-provider | `oqsprovider.so` (self-contained) | **523.9 KiB** | 1.69× |
| **Side B** this + hybrid-provider | `mldsanative.so` 211.1 KiB + `hybrid.so` 99.3 KiB | **310.5 KiB** | 1.0× |

`hybrid.so` (99.3 KiB) is pure EVP glue — it embeds no crypto; its ML-DSA comes
from `mldsanative.so` (shared with the plain-ML-DSA use), its ECDSA/RSA from the
default provider. oqs-provider instead statically embeds its own ML-DSA copy.

## Interop (all PASS, on OpenSSL 3.4.2)

Both cases are driven by a single table-driven program, `interop.c` (two library
contexts = two parties; `--benchmark` also times sign/verify each side):

- **Plain ML-DSA**, `mldsanative` ↔ `oqsprovider`, **raw-parameter** exchange
  (`OSSL_PKEY_PARAM_PUB_KEY`), cross sign/verify both ways, all three levels — 6/6.
- **Hybrids**, (`mldsanative`+`hybrid-provider`) ↔ `oqsprovider`, **SubjectPublic-
  KeyInfo DER** exchange (the two hybrid stacks do not share a raw-parameter
  layout, but their wire format is byte-compatible), both ways, all four hybrids
  — 8/8. The SPKI encodings are byte-identical in size across the two stacks
  (e.g. p256_mldsa44 = 1399 B, p521_mldsa87 = 2747 B).

## Speed (OpenSSL 3.4.2, x86_64 AVX2 both sides)

`interop.c --benchmark` times sign/verify on each side. Every figure is the
**best of 5 measurement windows of ≥ 1 s each** — each window runs thousands of
operations back-to-back, and reporting the best window discards transient
glitches (scheduler preemption, turbo ramp, background load) instead of averaging
them in, so the numbers are stable across runs. All figures are **throughput in
k ops/s (thousands of operations per second), so the bigger number is faster**;
the ratio column is ours ÷ oqs (> 1.0 = this provider faster). Two call paths are
measured:

- **one-shot** — a fresh `EVP_MD_CTX` with `EVP_DigestSign(Verify)Init` on every
  call. This is the real-world cost of a single detached sign/verify (X.509,
  CMS, a one-off signature), including the per-call provider fetch + context
  setup.
- **reused context** — one `EVP_PKEY_CTX` built once, then `EVP_PKEY_sign`/
  `EVP_PKEY_verify` back-to-back. This amortizes the plumbing away and exposes
  the crypto cost, the same method the nightly `ci/bench_regression.c` guard uses.

### Plain ML-DSA — one-shot (fresh context per call)

| algorithm | ours sign / verify (k ops/s ↑) | oqs sign / verify (k ops/s ↑) | ratio sign / verify |
|---|--:|--:|--:|
| ML-DSA-44 | 17.1 / 50.2 | 15.2 / 40.5 | **1.12× / 1.24×** |
| ML-DSA-65 | 10.9 / 30.7 | 9.5 / 23.6 | **1.14× / 1.30×** |
| ML-DSA-87 | 9.3 / 20.0 | 7.6 / 15.0 | **1.23× / 1.33×** |

### Plain ML-DSA — reused context (`EVP_PKEY_CTX` kept across calls)

| algorithm | ours sign / verify (k ops/s ↑) | oqs sign / verify (k ops/s ↑) | ratio sign / verify |
|---|--:|--:|--:|
| ML-DSA-44 | 17.6 / 52.2 | 15.5 / 42.4 | **1.14× / 1.23×** |
| ML-DSA-65 | 11.2 / 31.4 | 9.6 / 24.3 | **1.17× / 1.29×** |
| ML-DSA-87 | 9.5 / 20.5 | 7.8 / 15.5 | **1.23× / 1.32×** |

**The two paths agree to within ~3%** (e.g. ML-DSA-44 sign 17.1 vs 17.6, verify
50.2 vs 52.2). That is the key finding: for ML-DSA the per-call EVP plumbing
(provider fetch, context allocation, `DigestSignInit`) is a *negligible* fraction
of the lattice sign/verify arithmetic, so amortizing it barely moves the number.
This provider's **1.12–1.23× sign / 1.23–1.33× verify** advantage holds under
both regimes — it is a genuine crypto-path difference, not a plumbing artifact,
and it is not "init-dominated": for a primitive this expensive, context setup is
in the noise.

### ML-DSA hybrids — one-shot (fresh context per call)

| algorithm | ours sign / verify (k ops/s ↑) | oqs sign / verify (k ops/s ↑) | ratio sign / verify |
|---|--:|--:|--:|
| p256_mldsa44 | 12.2 / 13.1 | 11.2 / 12.4 | 1.10× / 1.05× |
| rsa3072_mldsa44 | 0.6 / 18.5 | 0.6 / 17.2 | 1.00× / 1.07× |
| p384_mldsa65 | 1.3 / 1.7 | 1.3 / 1.6 | 1.01× / 1.00× |
| p521_mldsa87 | 0.6 / 0.7 | 0.6 / 0.7 | 1.02× / 1.01× |

### ML-DSA hybrids — reused context (`EVP_PKEY_CTX` kept across calls)

| algorithm | ours sign / verify (k ops/s ↑) | oqs sign / verify (k ops/s ↑) | ratio sign / verify |
|---|--:|--:|--:|
| p256_mldsa44 | 12.6 / 13.2 | 11.7 / 12.9 | 1.08× / 1.03× |
| rsa3072_mldsa44 | 0.6 / 19.0 | 0.6 / 18.2 | 1.00× / 1.05× |
| p384_mldsa65 | 1.3 / 1.7 | 1.3 / 1.6 | 1.02× / 1.01× |
| p521_mldsa87 | 0.6 / 0.8 | 0.6 / 0.7 | 1.02× / 1.02× |

On the hybrids the two stacks are within ~10% on **both** paths: the classical half
(ECDSA/RSA from the default provider on both sides) dominates the cost, so the
ML-DSA component — where this provider's edge lives — is a small fraction of the
total. As with plain ML-DSA, the one-shot and reused numbers agree to within a few
percent — for a signature this expensive the per-call EVP plumbing is in the noise.

Both stacks compile the same mldsa-native AVX2 core, so these ratios reflect
provider glue over an identical algorithm, not an algorithmic difference.

## Functional mismatches / caveats (explicit)

1. **oqs-provider cedes ML-DSA on OpenSSL ≥ 3.5.** It runtime-disables
   `mldsa44/65/87` when `version >= 3.5.0` (defers to the native default
   provider). This provider never cedes. The interop therefore runs on 3.4.2,
   where oqs-provider actually serves ML-DSA. (Sizes are unaffected — the code is
   compiled either way.)
2. **Minimizing oqs-provider requires the `generate.yml` route**, not just a
   minimal liboqs. Otherwise ~90 phantom, non-functional algorithms remain
   advertised (the 1195.6 KiB row above).
3. **Plain ML-DSA interoperates at the raw-parameter level** (both providers use
   the identical raw public-key byte layout). **Hybrids do not** share the raw
   `OSSL_PKEY_PARAM_PUB_KEY` framing between oqs-provider and hybrid-provider;
   they interoperate at the **wire format** (SPKI/PKCS8 DER), which *is*
   byte-compatible. This is a representation difference, not a wire difference.
4. **hybrid-provider serves a superset by default.** Unmodified it serves 26
   signature + 42 KEM hybrids as glue; the 99.3 KiB figure is after
   trimming its tables to the four ML-DSA hybrids. Untrimmed it is ~403 KiB —
   still delivering 68 hybrids for less than oqs-provider's four, because it
   embeds no crypto.
5. **TLS-SIGALG capabilities are at parity below 3.5.** This provider implements
   `get_capabilities` (TLS 1.3 signature-scheme advertisement) for ML-DSA-44/65/87,
   gated to OpenSSL < 3.5 (on 3.5+ the native default provider does it, so this one
   stays out of the way). A live in-process TLS 1.3 handshake with an ML-DSA server
   certificate driven entirely by this provider passes for all three levels on
   3.4.2 (see `test/mldsa_tls_test.c`). Alongside this the provider carries the
   pieces the < 3.5 core otherwise lacks: OID/sigid registration (so X.509/CSR
   signing resolves the names), a manual SPKI decoder (so cert public keys decode),
   and cipher-aware/text PKCS#8 encoders. These features are part of the 211.1 KiB
   module measured above.
6. **liboqs's ML-DSA *is* mldsa-native** (vendored under
   `src/sig/ml_dsa/mldsa-native_*`), shipped un-deduplicated per level/backend —
   so the underlying algorithm code is identical; the size difference is
   packaging + library core + provider glue.

## Bottom line

For identical delivered functionality (ML-DSA + the four ML-DSA hybrids), the
`mldsanative + hybrid-provider` stack is **~1.7× smaller** than a minimal
oqs-provider (310.5 KiB vs 523.9 KiB), and the two interoperate in both
directions. For plain ML-DSA alone it is **~2.3× smaller** (211.1 KiB vs
494.9 KiB). Both stacks compile the same mldsa-native AVX2 core; on plain ML-DSA
this provider is also **1.12–1.23× faster at sign and 1.23–1.33× at verify**,
consistently whether the signing context is created per call (one-shot) or reused
(the two paths agree within ~3%, so the edge is real crypto, not plumbing). On
the hybrids the two are within ~10% — on both the one-shot and reused-context
paths — where the shared classical half dominates.
This provider additionally matches oqs-provider's plain-ML-DSA feature set below
OpenSSL 3.5 (TLS-SIGALG, OID/sigid registration, X.509/PKCS#8 codecs).

See `run.sh` for the exact reproduction steps and `interop.c` for the interop +
benchmark harness.
