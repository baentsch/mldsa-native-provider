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

### Code size and audit surface

Counting **everything needed to run ML-DSA**, this provider is **~21k lines**
(~2.0k provider logic + ~19k mldsa-native) versus **~163k** for oqs-provider
(~13.4k provider logic + ~20.6k liboqs core/API + ~129.5k ML-DSA — the *same*
mldsa-native code, but shipped as a separate copy per level × per backend). The
primitive's own risk is identical (both wrap mldsa-native); the honest
differentiator is the surrounding surface — a direct call here vs. liboqs's API
plus oqs-provider glue, and no EVP-composition or OID-patching machinery. Line
count alone is a weak proxy, but no intermediate layers and no extra runtime
dependencies genuinely lower audit and attack surface.

Full per-layer tables and an honest treatment of the "less code = less
vulnerability?" question: **[docs/COMPARISON.md](docs/COMPARISON.md)**. The
numbers are backed by a reproducible size/speed/interop experiment vs a minimal
oqs-provider (plain ML-DSA: **~2.3× smaller, 1.12–1.34× faster**, interop both
ways) — **[experiments/oqs-minimal-size/RESULTS.md](experiments/oqs-minimal-size/RESULTS.md)**.

## Interoperability

- **With the OpenSSL default provider (byte-for-byte).** Same 32-byte seed →
  identical public key; a signature from one provider verifies with the other in
  both directions; and `SubjectPublicKeyInfo` / `seed-priv` PKCS#8 written by one
  side is read by the other, with DER byte-identical in shape to the default
  provider's. Deterministic keygen/signing also reproduce the FIPS 204 KATs.
- **With the wider ecosystem.** Using **only this provider** for the ML-DSA
  operations, the `ietf_interop` test verifies the certificates and every
  private-key form published by **7 independent implementations** at
  [IETF-Hackathon/pqc-certificates](https://github.com/IETF-Hackathon/pqc-certificates)
  — **117 checks across all three levels, on both OpenSSL 3.4 and 3.5**.

Wire-format specifics (the `seed-priv` ASN.1 layout), the full implementation
list, and the < 3.5 X.509 caveats: **[docs/INTEROP.md](docs/INTEROP.md)**.

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
`openssl-3.5` branches on both **x86_64** and **aarch64** GitHub runners and runs
the full test suite on each. Benchmarking is deliberately kept **off** this
push/PR path; a nightly workflow (`.github/workflows/bench-regression.yml`)
instead regenerates the performance numbers (OpenSSL 3.5 + 4.0, both arches) and
guards against regressions vs both the default provider and oqs-provider — see
[docs/PERFORMANCE.md](docs/PERFORMANCE.md#how-ci-regenerates-and-guards-these-numbers).

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

On CPUs with an mldsa-native asm backend (x86_64 AVX2, AArch64 NEON) this
provider is several times faster than the default provider's portable-C ML-DSA.
The comparison only exists on **OpenSSL 3.5+** (before 3.5 the default has no
ML-DSA); this provider's own throughput is independent of the libcrypto version.
Speed-up vs the default provider, ML-DSA-65, `openssl speed` (**higher is
faster**):

| platform | keygen | sign | verify |
|---|--:|--:|--:|
| x86_64 — AMD Ryzen 7 5800U (AVX2) | 4.4× | 9.2× | 4.8× |
| aarch64 — Neoverse-N2 (NEON) | 3.2× | 6.7× | 3.6× |

Speed-up is **specific to the CPU and the build's backend** — measure on your own
hardware with `test/benchmark.sh` (`FORMAT=md` for a paste-ready table); don't
carry one machine's number to another. Full per-level and per-version tables,
methodology, reproduction, and the nightly CI perf gates:
**[docs/PERFORMANCE.md](docs/PERFORMANCE.md)**.

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
.github/workflows/            ci.yml: build + test (openssl-3.2/3.5, x86_64+aarch64)
                              bench-regression.yml: nightly perf gates + numbers
USAGE.md                    selecting default vs this provider (CLI / cnf / EVP)
docs/COMPARISON.md          code-size & audit-surface detail vs oqs/hybrid-provider
docs/INTEROP.md             default-provider parity + IETF cross-impl interop detail
docs/PERFORMANCE.md         full perf tables, methodology, reproduction, CI gates
experiments/oqs-minimal-size/  reproducible size/speed/interop study vs oqs-provider
```

## Dependencies & license

The provider code is Apache-2.0. The ML-DSA implementation is
[mldsa-native](https://github.com/pq-code-package/mldsa-native)
(Apache-2.0 OR ISC OR MIT), included as a pinned git submodule under
`third_party/mldsa-native/` (not copied into this repository); the exact commit
is recorded in git. Only small integration glue in `mldsa_glue/` (a multi-level
wrapper and our build config) lives in-tree.
