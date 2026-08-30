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
- All ML-DSA arithmetic comes **directly from mldsa-native**, pulled in as a
  **pinned git submodule** ([`third_party/mldsa-native`](third_party)) rather
  than copied into the tree. The provider does **not** delegate to OpenSSL's own
  ML-DSA or any other intermediate crypto API. The only OpenSSL crypto used is
  the DRBG (`RAND_bytes`), as the entropy source for key/seed generation.
- **Signatures only — no KEM.**
- **Usable end-to-end from OpenSSL 3.2**, not just 3.5: on cores that lack native
  ML-DSA (&lt; 3.5) the provider also registers the ML-DSA OIDs/sigids, advertises
  a TLS 1.3 signature-scheme (TLS-SIGALG) capability, and adds encrypted-PKCS#8 /
  text encoders — so certificates, CSRs and TLS handshakes work. On 3.5+ it adds
  none of this, deferring to the default provider.

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
| Crypto source | **mldsa-native, pinned submodule, called directly** | **liboqs** (external library, its C API) | **none of its own** — delegates to other providers via EVP |
| Abstraction layers | one: provider → mldsa-native function | two: provider → liboqs `OQS_SIG_*` → primitive | provider → EVP → whichever provider serves each half |
| Runtime dependencies | just `libcrypto` | `libcrypto` **+ liboqs** | `libcrypto` **+ ≥1 other provider** present at run time |
| OID / code-point handling | standard names/OIDs; `OBJ_create`/sigid + TLS-SIGALG **only on OpenSSL < 3.5** (idempotent, where the core lacks them), nothing on 3.5+ | runtime `OBJ_create`/code-point patching (always) | inherits component identities |
| Hybrid / composite logic | none | some | the entire point |

Structurally that makes this the *flat, single-purpose* member of the family:
no algorithm registry, no external crypto library, no runtime composition — the
provider is a thin, direct binding over one focused implementation. The only
runtime registration it does is conditional: on OpenSSL < 3.5 (which lacks native
ML-DSA) it registers the standard ML-DSA OIDs/sigids and a TLS-SIGALG capability
so certificates and TLS work; on 3.5+ it adds nothing, deferring to the core.

### Code size

Provider logic and tests are directly comparable across all three (measured with
`wc -l` over C/H sources; `hybrid-provider` also has shell harnesses):

| Component | mldsa-native-provider | [oqs-provider](https://github.com/open-quantum-safe/oqs-provider) | [hybrid-provider](https://github.com/baentsch/hybrid-provider) |
|---|--:|--:|--:|
| Provider logic (the code you audit) | **~2.0k** | ~13.4k | ~9.5k |
| Tests (excl. embedded KAT vectors) | ~0.5k C + 0.3k shell | ~3.3k C | ~12.3k C + 1.4k shell |

For the *crypto*, an apples-to-apples comparison counts **everything needed to
run ML-DSA** — i.e. what this provider embeds (mldsa-native) versus the
equivalent slice of liboqs (its common library core + its ML-DSA implementation,
which is itself mldsa-native¹). `hybrid-provider` is omitted here because it
embeds no crypto — it delegates ML-DSA to whichever provider serves it:

| Layer needed to run ML-DSA | mldsa-native-provider | [oqs-provider](https://github.com/open-quantum-safe/oqs-provider) |
|---|--:|--:|
| Provider logic | ~2.0k | ~13.4k |
| Library core (common + SIG API) | none | ~20.6k (liboqs `common` ~16.7k + `sig` API ~3.9k) |
| ML-DSA implementation (mldsa-native) | ~19k¹ | ~129.5k² |
| **Total to run ML-DSA** | **~21k** | **~163k** |

¹ [mldsa-native](https://github.com/pq-code-package/mldsa-native): ~18k C/H +
0.8k asm covering **all three levels** with the portable-C core plus x86_64/AArch64
backends, deduplicated across levels via one monolithic build.

² liboqs's ML-DSA **is the same mldsa-native code**, vendored under
`src/sig/ml_dsa/mldsa-native_ml-dsa-{44,65,87}_{ref,x86_64,aarch64}`. It ships a
**separate copy per level × per backend** (each `_ref` copy alone is ~9.8k,
replicated identically for 44/65/87) instead of one multi-level build — so for
*identical functionality* its ML-DSA footprint is ~7× the ~19k here. The
algorithm code is byte-for-byte the same upstream; the difference is packaging
plus liboqs's library core and API layer.

### Does less code mean less vulnerability potential?

Partly, and it is a fair argument — with caveats worth stating honestly:

- **Yes, in the ways that matter for attack/audit surface.** The provider logic
  you must review is ~2k lines versus ~9–13k, there is **no dependency on a
  large multi-algorithm library** (liboqs is ~343k lines of C/asm), and there is
  **no EVP-composition or OID-patching machinery**. Removing intermediate
  abstractions and dynamic dispatch eliminates whole classes of integration and
  misconfiguration bugs. Fewer lines and fewer moving parts genuinely lower the
  cost of a complete audit and the surface an attacker can reach.
- **The ML-DSA crypto itself is the same in both.** oqs-provider's ML-DSA *is*
  mldsa-native (vendored inside liboqs), so the primitive's own risk is identical
  — the honest differentiator is the surrounding surface (a direct call here vs.
  liboqs's API plus oqs-provider glue), not the algorithm implementation.
- **Even like-for-like, the ML-DSA path is much smaller here.** Counting
  everything needed to run ML-DSA (see the table above) it is ~21k vs ~163k — and
  that comparison already isolates ML-DSA, so it is *not* just scope: the
  difference is the absence of a library core/API layer and liboqs's per-level
  duplication of the same code. Where scope *does* explain size is the
  broader **provider-logic** count (oqs-provider and hybrid-provider carry more
  because they serve many algorithms, hybrids and composites).
- **The crypto still exists and still counts.** ~18k lines of mldsa-native are
  pulled in (as a pinned submodule) — it is simply single-purpose. Whatever
  assurance properties that
  upstream code has are the upstream's; they are **not** claims about this
  provider's overall code path. The provider's own glue (keymgmt, signature,
  encoders/decoders, parameter handling) is ordinary C and carries no such
  guarantees, so it must be judged on its own merits.
- **Pinning shifts, not removes, responsibility.** Pinning mldsa-native as a
  submodule means bumping it ourselves to pick up upstream fixes (a supply-chain
  duty), whereas a shared `liboqs` is patched in one place — though the pin is at
  least explicit and auditable in git.
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
openjdk, ossl35, safelogic, sanctum-secops) across all three levels — **117
checks, on both OpenSSL 3.4 and 3.5**. Because this provider now supplies the
X.509 machinery for ML-DSA below 3.5 (OID/sigid registration + SPKI/PKCS#8
codecs), the test no longer needs a 3.5 core; it self-skips only without network
access or if the provider cannot be loaded.

## OpenSSL version support

| OpenSSL | provider builds | KAT | X.509 / IETF cert interop | TLS 1.3 handshake | interop vs default |
|---|:-:|:-:|:-:|:-:|:-:|
| 3.2 – 3.4 | ✅ | ✅ | ✅ (via this provider) | ✅ (via this provider) | skipped¹ |
| 3.5+ | ✅ | ✅ | ✅ | ✅ (via default) | ✅ |

The provider itself only uses 3.0-era provider/EVP APIs, so it builds and its
FIPS-204 KAT passes from **OpenSSL 3.2** on (a compat header supplies the few
ML-DSA `OSSL_PARAM` name macros that were only added to the headers in 3.5).

Below 3.5 the default provider has no native ML-DSA, so this provider supplies
the pieces libcrypto/libssl would otherwise get from it — **only on < 3.5**, to
avoid duplicate registration on 3.5+: OID + signature-id registration (so
X.509/CSR/cert verification resolves the algorithm), a TLS-SIGALG capability (so
TLS 1.3 negotiates and uses ML-DSA), and cipher-aware/text PKCS#8 encoders. As a
result X.509 certificates, the IETF cross-implementation cert interop, and live
TLS 1.3 handshakes all work from **3.2** on. The one thing still gated to 3.5 is
¹ *interop against the default provider* — before 3.5 there simply is no native
ML-DSA to compare against, so that test self-skips. The `tls` test conversely
self-skips on 3.5+, where the capability is intentionally inactive (the default
provider advertises the schemes) and the handshake runs via the default.

CI (`.github/workflows/ci.yml`) builds against the `openssl-3.2` and
`openssl-3.5` branches on both **x86_64** and **aarch64** GitHub runners, runs
the full test suite on each, and (on 3.5) prints the benchmark so the
CPU-optimized numbers for the AVX2 and AArch64 asm backends are visible per
architecture.

## Build

Requires CMake 3.16+, a C11 compiler, and OpenSSL **3.2+** (tested floor;
**3.5+** for the default-provider and IETF cert interop).

The ML-DSA implementation is a git submodule, so clone recursively (or
initialise it after cloning):

```sh
git clone --recursive https://github.com/baentsch/mldsa-native-provider
# or, in an existing checkout:
git submodule update --init --recursive

cmake -S . -B build -DOPENSSL_ROOT_DIR=/path/to/openssl
cmake --build build
```

This produces `build/mldsanative.so`. To move to a newer mldsa-native, bump the
submodule (`git -C third_party/mldsa-native fetch && git -C third_party/mldsa-native
checkout <commit>`), rebuild, and commit the new pin.

### Build options

| `-DMLDSA_NATIVE_BACKEND=` | effect |
|---|---|
| `AUTO` (default) | mldsa-native's optimized **asm backend** on x86_64 (AVX2) / AArch64, else portable C |
| `NATIVE` | force the asm backend (configure error on unsupported CPUs) |
| `PORTABLE` | force portable C everywhere (apples-to-apples vs the default provider) |

The active backend is reported at configure time and in
`openssl list -providers -verbose -provider mldsanative` (the `build info` line).

> **x86_64 runtime requirement.** The x86_64 asm backend (AUTO/NATIVE) is built
> with `-mavx2 -mbmi2`; mldsa-native gates both its AVX2 assembly and the C that
> dispatches to it on `__AVX2__`, so these flags are what actually engage the
> native path (without them the build silently falls back to portable C — see the
> `native-backend` fix). Consequently an x86_64 native build **requires an
> AVX2-capable CPU at run time**. Build with `-DMLDSA_NATIVE_BACKEND=PORTABLE`
> for a universal x86_64 binary. AArch64 uses NEON (ARMv8-A baseline) and needs
> no extra flags.

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
while the default provider's ML-DSA is **portable C everywhere**, the speed-up is
platform-specific — measure on your target hardware. With the asm backend
actually engaged, both architectures see a large win over the portable-C default
(measured with `openssl speed` on OpenSSL 3.5, this provider vs the default):

| operation | x86_64 (AVX2) | aarch64 (Neoverse-N2, NEON) |
|---|--:|--:|
| ML-DSA-65 keygen | ~4.3× | ~3.2× |
| ML-DSA-65 sign   | ~9.0× | ~6.8× |
| ML-DSA-65 verify | ~4.6× | ~3.6× |

Signing gains the most (it is the most SHAKE/rejection-heavy), and the exact
ratios are CPU-specific — CI prints the per-architecture numbers on every run;
don't carry one machine's number to another. See the "Performance and platform
targeting" section of [USAGE.md](USAGE.md) for details
and caveats.

## Test

```sh
cd build
ctest --output-on-failure
```

- `kat`          — FIPS 204 known-answer tests through the provider (EVP API).
- `interop`      — parity / cross sign-verify / key-file round-trips against the
  default provider (self-skips on OpenSSL &lt; 3.5).
- `tls`          — in-process TLS 1.3 handshake with an ML-DSA server certificate
  driven by this provider's TLS-SIGALG capability, all three levels (runs on
  OpenSSL &lt; 3.5; self-skips on 3.5+, where the default provider advertises the
  schemes).
- `ietf_interop` — cross-implementation interop against the IETF
  pqc-certificates artifacts, from OpenSSL 3.2 on (self-skips without network).

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
                            (+ encrypted-PKCS8/text encoders & TLS-SIGALG on <3.5)
mldsa_native_compat.h       OSSL_PARAM name shims for OpenSSL 3.2-3.4 headers
mldsa_glue/                 multi-level wrapper + our config (MLD_CONFIG_FILE)
third_party/mldsa-native/   mldsa-native, pinned git submodule (the crypto)
test/                       KAT + interop tests, IETF interop + benchmark scripts
.github/workflows/ci.yml    CI: build + test against openssl-3.2 and openssl-3.5
USAGE.md                    selecting default vs this provider; performance & platforms
```

## Dependencies & license

The provider code is Apache-2.0. The ML-DSA implementation is
[mldsa-native](https://github.com/pq-code-package/mldsa-native)
(Apache-2.0 OR ISC OR MIT), included as a pinned git submodule under
`third_party/mldsa-native/` (not copied into this repository); the exact commit
is recorded in git. Only small integration glue in `mldsa_glue/` (a multi-level
wrapper and our build config) lives in-tree.
