# Experiment: minimal oqs-provider vs mldsa-native-provider (binary size + interop)

**Status:** local experiment (feature branch `experiment/oqs-minimal-size`), not
part of the shipped provider. All numbers are x86_64, `strip -s`, self-contained
modules (crypto statically linked), gcc `-O3`/Release. `mldsanative.so` is built
with its native backend (x86_64 AVX2 asm), matching the mldsa-native core that
liboqs — and therefore oqs-provider — also compiles. Reproduce with `run.sh`.

## Goal

An apples-to-apples comparison of the code that must ship to deliver the same
ML-DSA functionality two ways:

- **Side A — oqs-provider**, built against a *minimal* liboqs (ML-DSA only), with
  its `generate.yml` reduced so it serves exactly ML-DSA + the four ML-DSA
  concatenation hybrids.
- **Side B — this provider + hybrid-provider**: `mldsanative.so` delivers
  ML-DSA; `hybrid-provider` (composite OFF, tables trimmed to the same four
  hybrids) delivers the hybrids, sourcing its ML-DSA component **from
  mldsanative**.

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
- **hybrid-provider**: `-DHYBRID_COMPOSITE=OFF`; for the fair size its X-macro
  tables (`HYBRID_SIG_LIST`/`HYBRID_KEM_LIST` in `hybrid_prov.h`) were trimmed to
  the four ML-DSA hybrids and no KEM hybrids.

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

`interop.c --benchmark` times full one-shot sign/verify (thousands of ops/sec,
higher is better). Because both sides wrap the same mldsa-native AVX2 core, this
measures packaging/backend overhead, not the algorithm:

| algorithm | ours sign | ours verify | oqs sign | oqs verify |
|---|--:|--:|--:|--:|
| ML-DSA-44 | 18.0 | 52.4 | 15.6 | 41.3 |
| ML-DSA-65 | 11.4 | 31.6 | 10.0 | 24.7 |
| ML-DSA-87 | 10.1 | 21.5 | 8.1 | 15.8 |
| p256_mldsa44 | 12.7 | 13.6 | 11.7 | 12.6 |
| rsa3072_mldsa44 | 0.6 | 19.0 | 0.6 | 17.2 |
| p384_mldsa65 | 1.3 | 1.7 | 1.3 | 1.6 |
| p521_mldsa87 | 0.6 | 0.8 | 0.6 | 0.8 |

This provider is at parity or slightly ahead of oqs-provider across the board.
Note this one-shot path includes per-call EVP init, so it is init-dominated and
understates the crypto-only difference; for a crypto-level ours-vs-oqs number
(reused signing context) use `ci/bench_regression.c`, the nightly regression
guard, which bounds this provider within 1.5× of oqs-provider on keygen/sign.

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
4. **hybrid-provider serves a superset by default.** Unmodified (composite OFF)
   it serves 26 signature + 42 KEM hybrids as glue; the 99.3 KiB figure is after
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
6. **Composite** signatures were intentionally NOT built into hybrid-provider
   (`-DHYBRID_COMPOSITE=OFF`); the ML-DSA-only oqs-provider has none either.
7. **liboqs's ML-DSA *is* mldsa-native** (vendored under
   `src/sig/ml_dsa/mldsa-native_*`), shipped un-deduplicated per level/backend —
   so the underlying algorithm code is identical; the size difference is
   packaging + library core + provider glue.

## Bottom line

For identical delivered functionality (ML-DSA + the four ML-DSA hybrids), the
`mldsanative + hybrid-provider` stack is **~1.7× smaller** than a minimal
oqs-provider (310.5 KiB vs 523.9 KiB), and the two interoperate in both
directions. For plain ML-DSA alone it is **~2.3× smaller** (211.1 KiB vs
494.9 KiB). Both stacks compile the same mldsa-native AVX2 core, so their
ML-DSA speed is equivalent (this provider measures at parity or slightly ahead
in the one-shot interop benchmark). This provider additionally matches
oqs-provider's plain-ML-DSA feature set below OpenSSL 3.5 (TLS-SIGALG,
OID/sigid registration, X.509/PKCS#8 codecs).

See `run.sh` for the exact reproduction steps and `interop.c` for the interop +
benchmark harness.
