# mldsa-native-provider

An external OpenSSL 3.2+ provider implementing **ML-DSA** (FIPS 204) digital
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
[hybrid-provider](https://github.com/baentsch/hybrid-provider) and
[oqs-provider](https://github.com/open-quantum-safe/oqs-provider),
which compose or delegate to other providers/libraries: here the FIPS 204 core
is mldsa-native and nothing else.

## How it compares to [oqs-provider](https://github.com/open-quantum-safe/oqs-provider) and [hybrid-provider](https://github.com/baentsch/hybrid-provider)

The three providers occupy deliberately different points in the design space:

| | **mldsa-native-provider** | **[oqs-provider](https://github.com/open-quantum-safe/oqs-provider)** | **[hybrid-provider](https://github.com/baentsch/hybrid-provider)** |
|---|---|---|---|
| Scope | ML-DSA signatures only | all liboqs PQ KEMs **and** signatures (dozens) | hybrid + composite KEMs and signatures (many) |
| Crypto source | **mldsa-native, vendored, called directly** | **liboqs** (external library, its C API) | **none of its own** — delegates to other providers via EVP |
| Abstraction layers | one: provider → mldsa-native function | two: provider → liboqs `OQS_SIG_*` → primitive | provider → EVP → whichever provider serves each half |
| Runtime dependencies | just `libcrypto` | `libcrypto` **+ liboqs** | `libcrypto` **+ ≥1 other provider** present at run time |
| OID / code-point handling | standard names/OIDs, no patching | runtime `OBJ_create`/code-point patching | inherits component identities |
| Hybrid / composite logic | none | some | the entire point |

Structurally that makes this the *flat, single-purpose* member of the family:
no algorithm registry, no external crypto library, no runtime composition, no
OID patching — the provider is a thin, direct binding over one focused
implementation.

### Code size

Measured with `wc -l` over C/H (and asm) sources in each repository:

| Component | mldsa-native-provider | [oqs-provider](https://github.com/open-quantum-safe/oqs-provider) | [hybrid-provider](https://github.com/baentsch/hybrid-provider) |
|---|--:|--:|--:|
| Provider logic (the code you audit) | **~2.0k** | ~13.4k | ~9.5k |
| Bundled crypto | mldsa-native ~18k C/H + 0.8k asm¹ | none bundled | none bundled |
| External crypto dependency | none | **liboqs ~174k** | other providers (varies) |
| Tests (excl. embedded KAT vectors) | ~0.5k C + 0.3k shell | ~3.3k C | ~12.3k C + 1.4k shell |

¹ [mldsa-native](https://github.com/pq-code-package/mldsa-native) covers all
three ML-DSA levels with a portable-C core (~11.5k) plus optional x86_64/AArch64
backends (~4k C + 0.8k asm).

### Does less code mean less vulnerability potential?

Partly, and it is a fair argument — with caveats worth stating honestly:

- **Yes, in the ways that matter for attack/audit surface.** The provider logic
  you must review is ~2k lines versus ~9–13k, there is **no dependency on a
  ~174k-line multi-algorithm library**, and there is **no EVP-composition or
  OID-patching machinery**. Removing intermediate abstractions and dynamic
  dispatch eliminates whole classes of integration and misconfiguration bugs.
  Fewer lines and fewer moving parts genuinely lower the cost of a complete
  audit and the surface an attacker can reach.
- **But it is not a like-for-like comparison.**
  [oqs-provider](https://github.com/open-quantum-safe/oqs-provider) and
  [hybrid-provider](https://github.com/baentsch/hybrid-provider)
  are smaller-per-algorithm precisely because they are *broader by design*
  (many algorithms, hybrids, composites). Most of this provider's smallness is
  scope, not superior engineering.
- **The crypto still exists and still counts.** We vendor ~18k lines of
  mldsa-native — it is simply single-purpose. Whatever assurance properties that
  upstream code has are the upstream's; they are **not** claims about this
  provider's overall code path. The provider's own glue (keymgmt, signature,
  encoders/decoders, parameter handling) is ordinary C and carries no such
  guarantees, so it must be judged on its own merits.
- **Vendoring shifts, not removes, responsibility.** Pinning a copy of
  mldsa-native means tracking upstream fixes ourselves (a supply-chain duty),
  whereas a shared `liboqs` is patched in one place.
- **LOC is a weak proxy.** Complexity, memory safety, and test coverage predict
  vulnerabilities far better than line count.

Bottom line: the smaller, dependency-light, single-purpose design does reduce
attack surface and audit burden — but the durable benefits come from **no
intermediate layers, no extra runtime dependencies, and a small single-purpose
surface**, more than from the line count itself.

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
`openssl-3.5` branches on both **x86_64** and **aarch64** GitHub runners, runs
the full test suite on each, and (on 3.5) prints the benchmark so the
CPU-optimized numbers for the AVX2 and AArch64 asm backends are visible per
architecture.

## Build

Requires CMake 3.16+, a C11 compiler, and OpenSSL **3.2+** (tested floor;
**3.5+** for the default-provider and IETF cert interop).

```sh
cmake -S . -B build -DOPENSSL_ROOT_DIR=/path/to/openssl
cmake --build build
```

This produces `build/mldsanative.so`.

### Build options

| `-DMLDSA_NATIVE_BACKEND=` | effect |
|---|---|
| `AUTO` (default) | mldsa-native's optimized **asm backend** on x86_64 (AVX2) / AArch64, else portable C |
| `NATIVE` | force the asm backend (configure error on unsupported CPUs) |
| `PORTABLE` | force portable C everywhere (apples-to-apples vs the default provider) |

The active backend is reported at configure time and in
`openssl list -providers -verbose -provider mldsanative` (the `build info` line).

## Selecting which ML-DSA runs (default vs this provider)

There is **no cede-to-default logic**: when both providers are loaded they both
offer `ML-DSA-44/65/87`, so you pick the implementation explicitly with a
property query — `-propquery '?provider=mldsanative'` or `'?provider=default'`
on the CLI, `default_properties` in `openssl.cnf`, or the propquery argument in
the EVP API. **[USAGE.md](USAGE.md)** documents all three with worked examples.

## Performance

`test/benchmark.sh` is a worked `openssl speed` example that runs each level
under both providers (differing only in the property query) and prints a
comparison plus the machine and active backend:

```sh
OPENSSL=/path/to/openssl OPENSSL_LIBPATH=/path/to/openssl/lib \
MODULE_DIR=$PWD/build  test/benchmark.sh
```

Because mldsa-native is optimized for **specific CPUs** (x86_64 AVX2, AArch64)
while the default provider's ML-DSA is **portable C everywhere**, the speed-up
is platform-specific — measure on your target hardware. As a vivid illustration,
the CI benchmark (this provider vs the default provider, same OpenSSL 3.5) gives
very different ratios per architecture:

| operation | x86_64 (AMD EPYC 7763, AVX2) | aarch64 (Neoverse-N2) |
|---|--:|--:|
| ML-DSA-65 keygen | ~1.5× | ~3.2× |
| ML-DSA-65 sign   | ~2.0× | ~6.8× |
| ML-DSA-65 verify | ~1.5× | ~3.6× |

Same code, same algorithm — the AArch64 backend simply wins more over portable
C on that core. Don't carry one architecture's number to another. See the
"Performance and platform targeting" section of [USAGE.md](USAGE.md) for details
and caveats.

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
test/                       KAT + interop tests, IETF interop + benchmark scripts
.github/workflows/ci.yml    CI: build + test against openssl-3.2 and openssl-3.5
USAGE.md                    selecting default vs this provider; performance & platforms
```

## Vendored code & license

The provider code is Apache-2.0. `vendor/` contains a snapshot of
[mldsa-native](https://github.com/pq-code-package/mldsa-native)
(Apache-2.0 OR ISC OR MIT); see `vendor/mldsa_native/` for its notices.
