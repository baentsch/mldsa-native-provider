# mldsa-native-provider

An external OpenSSL 3.5+ provider implementing **ML-DSA** (FIPS 204) digital
signatures — and nothing else — on top of the
[mldsa-native](https://github.com/pq-code-package/mldsa-native) implementation.

> ⚠️ **AI-generated — not for production use.** Like
> [oqs-provider](https://github.com/open-quantum-safe/oqs-provider), this is a
> vehicle for experimentation and interoperability research. It has not been
> reviewed or audited to production standards.

## What it is

- Serves **ML-DSA-44 / ML-DSA-65 / ML-DSA-87** as keymgmt + signature +
  encoder/decoder operations under the standard names, OIDs and TLS/PKIX
  identifiers (`2.16.840.1.101.3.4.3.17/.18/.19`).
- All ML-DSA arithmetic comes **directly from mldsa-native** (vendored under
  [`vendor/`](vendor)). The provider does **not** delegate to OpenSSL's own
  ML-DSA or any other intermediate crypto API. The only OpenSSL crypto used is
  the DRBG (`RAND_bytes`), as the entropy source for key/seed generation.
- **Signatures only — no KEM.**

This differs from its siblings
[hybrid-provider](https://github.com/baentsch/hybrid-provider) and oqs-provider,
which compose or delegate to other providers/libraries: here the FIPS 204 core
is mldsa-native and nothing else.

## Interoperability with the OpenSSL default provider

Verified by the test suite and byte-for-byte against OpenSSL 3.5's default
provider:

- **Seed-expansion parity** — importing the same 32-byte seed into both
  providers yields the identical public key.
- **Cross sign/verify** — a signature produced by one provider verifies with
  the other, in both directions (pure ML-DSA, empty context).
- **Key-file formats** — public keys as `SubjectPublicKeyInfo` (raw key in the
  BIT STRING) and private keys as PKCS#8 in the default provider's `seed-priv`
  form: `privateKey OCTET STRING { SEQUENCE { OCTET STRING seed(32),
  OCTET STRING expandedKey } }`. PEM/DER written by one side is read by the
  other; the DER is byte-identical in shape to the default provider's.
- **Known-answer tests** — deterministic keygen and signing reproduce the
  FIPS 204 test vectors shipped with mldsa-native.

## Cross-implementation interop (IETF pqc-certificates)

The `ietf_interop` test consumes the ML-DSA artifacts published by many
independent implementations at
[IETF-Hackathon/pqc-certificates](https://github.com/IETF-Hackathon/pqc-certificates)
and, using **only this provider** for the ML-DSA operations, checks that each
implementation's self-signed trust-anchor certificate verifies and that every
private-key form they ship (`seed` / `expandedKey` / `both`) loads and signs.
It currently passes against **7 implementations** (bc, botan, carl-redhound,
openjdk, ossl35, safelogic, sanctum-secops) across all three levels. It
self-skips without network access or on OpenSSL &lt; 3.5 (X.509 ML-DSA handling
is a 3.5 libcrypto feature).

## OpenSSL version support

| OpenSSL | provider builds | KAT | interop vs default | IETF cert interop |
|---|:-:|:-:|:-:|:-:|
| 3.2 – 3.4 | ✅ | ✅ | skipped¹ | skipped² |
| 3.5+ | ✅ | ✅ | ✅ | ✅ |

The provider itself only uses 3.0-era provider/EVP APIs, so it builds and its
FIPS-204 KAT passes from **OpenSSL 3.2** on (a compat header supplies the few
ML-DSA `OSSL_PARAM` name macros that were only added to the headers in 3.5).
The things that genuinely need 3.5 are *comparisons/plumbing outside this
provider*: ¹ the default provider gained ML-DSA in 3.5, so there is nothing to
interop against before then; ² libcrypto's X.509 certificate machinery only
understands ML-DSA from 3.5. Both tests self-skip below 3.5 rather than fail.

CI (`.github/workflows/ci.yml`) builds against the `openssl-3.2` and
`openssl-3.5` branches and runs the full test suite on each.

## Build

Requires CMake 3.16+, a C11 compiler, and OpenSSL **3.2+** (tested floor;
**3.5+** for the default-provider and IETF cert interop).

```sh
cmake -S . -B build -DOPENSSL_ROOT_DIR=/path/to/openssl-3.5
cmake --build build
```

This produces `build/mldsanative.so`.

## Test

```sh
cd build
ctest --output-on-failure
```

- `kat`          — FIPS 204 known-answer tests through the provider (EVP API).
- `interop`      — parity / cross sign-verify / key-file round-trips against the
  default provider (self-skips on OpenSSL &lt; 3.5).
- `ietf_interop` — cross-implementation interop against the IETF
  pqc-certificates artifacts (self-skips without network or on &lt; 3.5).

To use the provider from the CLI, point `OPENSSL_MODULES` at the build
directory:

```sh
export OPENSSL_MODULES=$PWD/build
openssl list -signature-algorithms -provider mldsanative
openssl genpkey -provider mldsanative -provider default \
    -propquery '?provider=mldsanative' -algorithm ML-DSA-65 -out key.pem
```

## Layout

```
mldsa_native_prov.{c,h}     provider entry, algorithm tables, param sets, RNG hook
mldsa_native_keymgmt.c      keymgmt: seed/pub/priv import-export, keygen, params
mldsa_native_sig.c          signature: pure ML-DSA sign/verify (+ context, KAT entropy)
mldsa_native_encoder.c      SPKI + PKCS8 encoders (DER + PEM)
mldsa_native_decoder.c      SPKI + PKCS8 decoders (DER; PEM via OpenSSL pem2der)
mldsa_native_compat.h       OSSL_PARAM name shims for OpenSSL 3.2-3.4 headers
vendor/                     vendored mldsa-native (multi-level monolithic build)
test/                       KAT + interop tests, IETF interop script, FIPS 204 vectors
.github/workflows/ci.yml    CI: build + test against openssl-3.2 and openssl-3.5
```

## Vendored code & license

The provider code is Apache-2.0. `vendor/` contains a snapshot of
[mldsa-native](https://github.com/pq-code-package/mldsa-native)
(Apache-2.0 OR ISC OR MIT); see `vendor/mldsa_native/` for its notices.
