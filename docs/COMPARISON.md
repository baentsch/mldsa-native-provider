# Code size and audit-surface comparison

Detail behind the "How it compares" section of the [README](../README.md#how-it-compares-to-oqs-provider-and-hybrid-provider),
which has the at-a-glance scope/crypto-source/abstraction-layers matrix for
mldsa-native-provider vs [oqs-provider](https://github.com/open-quantum-safe/oqs-provider)
and [hybrid-provider](https://github.com/baentsch/hybrid-provider). This file
covers the code-size numbers and what they do (and do not) imply for
vulnerability surface.

## Code size

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

## Does less code mean less vulnerability potential?

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

## Measured head-to-head vs oqs-provider (binary size, speed, interop)

The source-line counts above are backed by an empirical, reproducible experiment
that builds a *minimal* oqs-provider (ML-DSA only) and compares stripped module
size, sign/verify throughput, and cross-provider interop against this provider on
the same machine and the same mldsa-native core. Summary: for plain ML-DSA this
provider is **~2.3× smaller** and **1.12–1.34× faster**, and the two interoperate
in both directions. Full method, tables and caveats:
**[experiments/oqs-minimal-size/RESULTS.md](../experiments/oqs-minimal-size/RESULTS.md)**
(reproduce with its `run.sh`).
