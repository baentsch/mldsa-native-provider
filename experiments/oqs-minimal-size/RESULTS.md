# Experiment: minimal oqs-provider vs mldsa-native-provider (binary size + interop)

**Status:** local experiment (feature branch `experiment/oqs-minimal-size`), not
part of the shipped provider. All numbers are x86_64, `strip -s`, self-contained
modules (crypto statically linked), gcc `-O3`/Release.

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
| `mldsanative.so` (this provider) | **167.0 KiB** | 1.0× |
| `oqsprovider.so`, regenerated ML-DSA-only | 494.9 KiB | 3.0× |
| `oqsprovider.so`, minimal liboqs but **tables not regenerated** | 1195.6 KiB | 7.2× |

`mldsanative.so` grew from 154.9 → 167.0 KiB (+12 KiB, +7.8%) when the OpenSSL
< 3.5 parity features were added (TLS-SIGALG capability, OID/sigid registration,
cipher-aware/text encoders, and the manual SPKI decoder). It remains the
smallest module by a wide margin.

The last row shows why regeneration matters: without editing `generate.yml`,
oqs-provider still advertises ~90 algorithms (all non-ML-DSA ones are
**non-functional** — `genpkey falcon512` → "Could not create OQS signature
algorithm Falcon-512. Enabled in liboqs?"). Regeneration removes them.

Enabling the four ML-DSA hybrids in oqs-provider adds only **+29 KiB (+5.9%)**
(494.9 → 523.9 KiB): the hybrid-composition code is already compiled in, so
hybrids are essentially table entries.

### Functionally equivalent stacks: ML-DSA + the 4 ML-DSA hybrids

| stack | modules | size | ratio |
|---|---|--:|--:|
| **Side A** oqs-provider | `oqsprovider.so` (self-contained) | **523.9 KiB** | 1.97× |
| **Side B** this + hybrid-provider | `mldsanative.so` 167.0 KiB + `hybrid.so` 99.3 KiB | **266.3 KiB** | 1.0× |

`hybrid.so` is pure EVP glue — it embeds no crypto; its ML-DSA comes from
`mldsanative.so` (shared with the plain-ML-DSA use), its ECDSA/RSA from the
default provider. oqs-provider instead statically embeds its own ML-DSA copy.

## Interop (all PASS, on OpenSSL 3.4.2)

- **Plain ML-DSA**, `mldsanative` ↔ `oqsprovider`, raw-pubkey exchange,
  cross sign/verify both ways, all three levels — 6/6
  (`oqs_vs_mldsanative_interop.c`).
- **Hybrids**, (`mldsanative`+`hybrid-provider`) ↔ `oqsprovider`, SubjectPublic-
  KeyInfo DER exchange, cross sign/verify both ways, all four hybrids — 8/8
  (`hybrid_interop.c`). The SPKI encodings are byte-identical in size across the
  two stacks (e.g. p256_mldsa44 = 1399 B, p521_mldsa87 = 2747 B).

## Functional mismatches / caveats (explicit)

1. **oqs-provider cedes ML-DSA on OpenSSL ≥ 3.5.** It runtime-disables
   `mldsa44/65/87` when `version >= 3.5.0` (defers to the native default
   provider). This provider never cedes. The interop therefore runs on 3.4.2,
   where oqs-provider actually serves ML-DSA. (Sizes are unaffected — the code is
   compiled either way.)
2. **Minimizing oqs-provider requires the `generate.yml` route**, not just a
   minimal liboqs. Otherwise ~90 phantom, non-functional algorithms remain
   advertised.
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
5. **TLS-SIGALG capabilities — now at parity.** This provider now implements
   `get_capabilities` (TLS 1.3 signature-scheme advertisement) for ML-DSA-44/65/87,
   gated to OpenSSL < 3.5 (on 3.5+ the native default provider does it, so this one
   stays out of the way). A live in-process TLS 1.3 handshake with an ML-DSA server
   certificate driven entirely by this provider passes for all three levels on
   3.4.2 (see `test/mldsa_tls_test.c`). Alongside this the provider gained the
   pieces the < 3.5 core otherwise lacks: OID/sigid registration (so X.509/CSR
   signing resolves the names), a manual SPKI decoder (so cert public keys decode),
   and cipher-aware/text PKCS#8 encoders. The earlier plain-ML-DSA-in-TLS gap is
   closed; the +12 KiB in the size table above is the cost of these features.
6. **Composite** signatures were intentionally NOT built into hybrid-provider
   (`-DHYBRID_COMPOSITE=OFF`); the ML-DSA-only oqs-provider has none either.
7. **liboqs's ML-DSA *is* mldsa-native** (vendored under
   `src/sig/ml_dsa/mldsa-native_*`), shipped un-deduplicated per level/backend —
   so the underlying algorithm code is identical; the size difference is
   packaging + library core + provider glue.

## Bottom line

For identical delivered functionality (ML-DSA + the four ML-DSA hybrids), the
`mldsanative + hybrid-provider` stack is **~2× smaller** than a minimal
oqs-provider (266 KiB vs 524 KiB), and the two interoperate in both directions.
For plain ML-DSA alone it is **~3.0× smaller** (167 KiB vs 495 KiB). With the
< 3.5 parity work (TLS-SIGALG, OID/sigid registration, X.509/PKCS#8 codecs) the
earlier plain-ML-DSA-in-TLS functional gap is now closed, at a cost of +12 KiB —
the stack stays the smaller of the two while now matching oqs-provider's
plain-ML-DSA feature set below 3.5.

See `run.sh` for the exact reproduction steps and `*.c` for the interop tests.
