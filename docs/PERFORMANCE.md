# Performance and platform targeting

Full detail behind the Performance summary in the
[README](../README.md#performance): per-level tables, cross-version numbers,
methodology, how to reproduce them in your own environment, and how CI regenerates
and guards them.

## How to measure it yourself

`test/benchmark.sh` is a worked `openssl speed` example that runs each level
under both providers (differing only in the property query) and prints a
comparison plus the machine and active backend:

```sh
OPENSSL=/path/to/openssl OPENSSL_LIBPATH=/path/to/openssl/lib \
MODULE_DIR=$PWD/build  test/benchmark.sh
# add FORMAT=md for a Markdown table ready to paste into docs
```

Point `OPENSSL`/`OPENSSL_LIBPATH` at an OpenSSL **≥ 3.5** install (the default
provider only ships ML-DSA from 3.5 on) and `MODULE_DIR` at a build of this
provider against that same OpenSSL.

All figures below are `openssl speed`, 2-second windows, this provider's native
asm backend vs the default provider's portable-C ML-DSA, speed-up = this ÷
default (**higher is faster**). Because mldsa-native is optimized for **specific
CPUs** (x86_64 AVX2, AArch64) while the default provider's ML-DSA is **portable C
everywhere**, the speed-up is platform-specific — **measure on your target
hardware**; the tables below are illustrative of two representative machines, not
a promise for yours. The comparison against the default provider only exists on
**OpenSSL 3.5+** — before 3.5 the default provider has no ML-DSA at all, so there
is nothing to compare against (this provider still runs; see the version table
below).

## Speed-up vs the default provider, by platform (OpenSSL 3.5)

**x86_64 — AMD Ryzen 7 5800U (AVX2)**

| operation | ML-DSA-44 | ML-DSA-65 | ML-DSA-87 |
|---|--:|--:|--:|
| keygen | 4.5× | 4.4× | 4.2× |
| sign   | 8.7× | 9.2× | 9.1× |
| verify | 5.0× | 4.8× | 4.9× |

**aarch64 — Neoverse-N2 (NEON, GitHub `ubuntu-24.04-arm` runner)**

| operation | ML-DSA-44 | ML-DSA-65 | ML-DSA-87 |
|---|--:|--:|--:|
| keygen | 3.2× | 3.2× | 2.9× |
| sign   | 6.5× | 6.7× | 6.0× |
| verify | 3.9× | 3.6× | 3.3× |

Signing gains the most (it is the most SHAKE/rejection-heavy). The absolute
throughput behind the x86_64 ML-DSA-65 column, for scale: default ≈ 6.9k keygen /
1.2k sign / 6.9k verify ops·s⁻¹ versus this provider ≈ 30.8k / 11.9k / 33.7k.

## Across OpenSSL versions (x86_64, AMD Ryzen 7 5800U)

This provider carries its own mldsa-native core, so its ML-DSA throughput is
**independent of the libcrypto version**; the default provider's ML-DSA (the
comparison baseline) only appears at 3.5. ML-DSA-65 speed-up vs default:

| OpenSSL | keygen | sign | verify | notes |
|---|--:|--:|--:|:--|
| 3.2 – 3.4 | — | — | — | default has no ML-DSA to compare against¹ |
| 3.5.6 | 4.4× | 9.2× | 4.8× | |
| 4.0.1 | 4.5× | 8.8× | 4.7× | within run-to-run noise of 3.5 |

¹ The provider itself runs and delivers ML-DSA on 3.2–3.4 (this is the whole
point of the &lt; 3.5 support); its measured throughput there matches 3.5/4.0 to
within a few percent. Note the `openssl speed` CLI can only *target* ML-DSA from
**3.4** on, so on 3.2 use the KAT/interop tests rather than `speed`.

## Reading the numbers with the platform in mind

- **mldsa-native** ships CPU-optimized **assembly backends for x86_64 (AVX2) and
  AArch64**. On those CPUs this provider runs the native backend and is markedly
  faster than the portable-C default. On any other architecture — or when built
  with `-DMLDSA_NATIVE_BACKEND=PORTABLE` — it uses portable C.
- **OpenSSL's default-provider ML-DSA is portable C on every platform.**
- So any speed-up figure is **specific to the CPU and the build's backend**. Do
  not carry an x86_64-AVX2 result over to a portable-C or non-supported
  architecture. The active backend is shown in
  `openssl list -providers -verbose` (the `build info` line) and in the benchmark
  header.

Backend selection at build time (see also the [README build options](../README.md#build-options)):

| `-DMLDSA_NATIVE_BACKEND=` | effect |
|---|---|
| `AUTO` (default) | native asm on x86_64/AArch64, else portable C |
| `NATIVE` | force native asm (errors on unsupported CPUs) |
| `PORTABLE` | force portable C everywhere (apples-to-apples vs default) |

## How CI regenerates and guards these numbers

Benchmarking is kept **off** the push/PR path (it is wasteful and noisy on shared
runners). Instead the nightly workflow
[`.github/workflows/bench-regression.yml`](../.github/workflows/bench-regression.yml)
runs two performance guards on both x86_64 and aarch64:

- **`perf-numbers`** runs `test/benchmark.sh` against `openssl-3.5` and
  `openssl-4.0`, publishing a Markdown table to each job summary — so the tables
  above can be refreshed from a recent nightly run rather than re-measured by
  hand. It also **fails, opening a per-arch/per-version tracking issue, if any op
  drops below `MLDSA_MIN_SPEEDUP` (2×) vs the default provider.**
- **`bench`** guards analogously against the native backend regressing relative
  to oqs-provider (which wraps the same mldsa-native core), on OpenSSL 3.4 where
  oqs-provider serves ML-DSA.

Both catch the same underlying failure — the asm backend silently falling back to
portable C, which collapses the speed-up toward ~1× — from two angles. When that
happens, check that the build still passes `-mavx2` (x86_64) and reports
`native ... asm` in its `build info` line.
