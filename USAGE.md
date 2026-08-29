# Using the mldsa-native provider: selecting which ML-DSA runs

This provider does **not** cede to the default provider. When both are loaded in
the same library context, **both** advertise `ML-DSA-44/65/87` under the same
names and OIDs (`2.16.840.1.101.3.4.3.17/.18/.19`). Which implementation
actually runs for a given operation is therefore **your choice**, expressed with
a property query. Without one, selection falls back to load order and is not
guaranteed — so always select explicitly for reproducible behaviour.

Two provider identities are relevant:

| You want ML-DSA from… | property query |
|---|---|
| this provider (mldsa-native) | `?provider=mldsanative` |
| OpenSSL's built-in implementation | `?provider=default` |

`?` makes it a *preference* (fetch still succeeds if only one provider is
present); drop the `?` to make it *mandatory* (fetch fails if that provider
can't supply the algorithm). Prefer `?provider=…` in mixed setups.

## 1. Loading the provider

The build produces `mldsanative.so`. Point OpenSSL at the directory containing
it (or install it into the OpenSSL modules directory):

```sh
export OPENSSL_MODULES=/path/to/build      # dir holding mldsanative.so
openssl list -providers -provider mldsanative -verbose
# ... build info: 0.1.0 [native (x86_64 asm)]   <-- shows the active backend
```

## 2. Command line: `-provider` + `-propquery`

Load both providers and pick the implementation with `-propquery`. The commands
below are identical except for that query — that *is* the selection mechanism.

```sh
# Generate an ML-DSA-65 key with THIS provider
openssl genpkey -provider mldsanative -provider default \
    -propquery '?provider=mldsanative' -algorithm ML-DSA-65 -out key.pem

# Generate the same with OpenSSL's built-in ML-DSA
openssl genpkey -provider default \
    -propquery '?provider=default' -algorithm ML-DSA-65 -out key-default.pem

# Sign / verify a raw message, forcing this provider
openssl pkeyutl -provider mldsanative -provider default \
    -propquery '?provider=mldsanative' \
    -sign -inkey key.pem -rawin -in msg.bin -out sig.bin
openssl pkeyutl -provider mldsanative -provider default \
    -propquery '?provider=mldsanative' \
    -verify -inkey key.pem -rawin -in msg.bin -sigfile sig.bin

# Benchmark either implementation (see also test/benchmark.sh)
openssl speed -provider mldsanative -provider default \
    -propquery '?provider=mldsanative' ML-DSA-65
```

Because the key formats are byte-compatible, you can generate with one provider
and verify/consume with the other (that is exactly what the interop tests do).

## 3. Config file (`openssl.cnf`)

To make the choice process-wide without passing flags every time, activate the
provider and set a default property query:

```ini
openssl_conf = openssl_init

[openssl_init]
providers = provider_sect
alg_section = algorithm_sect

[provider_sect]
default     = default_sect
mldsanative = mldsanative_sect

[default_sect]
activate = 1

[mldsanative_sect]
activate = 1
# module = /path/to/mldsanative.so   # or rely on OPENSSL_MODULES

[algorithm_sect]
# Route ML-DSA (and everything else it can serve) to this provider by default.
default_properties = ?provider=mldsanative
```

Use it with `OPENSSL_CONF=/path/to/that.cnf`. Switch the whole process back to
OpenSSL's implementation by changing the one line to
`default_properties = ?provider=default`.

## 4. Programmatically (C / EVP)

```c
OSSL_LIB_CTX  *libctx = OSSL_LIB_CTX_new();
OSSL_PROVIDER_set_default_search_path(libctx, "/path/to/build");
OSSL_PROVIDER_load(libctx, "default");
OSSL_PROVIDER_load(libctx, "mldsanative");

/* Per-operation selection via the propquery argument: */
EVP_PKEY_CTX *ctx =
    EVP_PKEY_CTX_new_from_name(libctx, "ML-DSA-65", "provider=mldsanative");

/* Or process-wide default for this libctx: */
EVP_set_default_properties(libctx, "?provider=mldsanative");
```

## 5. Performance and platform targeting

A benchmark is provided as a worked example of the selection above:

```sh
OPENSSL=/path/to/openssl OPENSSL_LIBPATH=/path/to/openssl/lib \
MODULE_DIR=/path/to/build  test/benchmark.sh
```

It runs `openssl speed` for each level under both providers and prints a
comparison plus the machine and the active backend.

**Read the numbers with the platform in mind:**

- **mldsa-native** ships CPU-optimized **assembly backends for x86_64 (AVX2)
  and AArch64**. On those CPUs this provider runs the native backend and is
  markedly faster (roughly 1.4–2× on keygen/sign/verify in our x86_64 runs).
  On any other architecture — or when built with
  `-DMLDSA_NATIVE_BACKEND=PORTABLE` — it uses portable C.
- **OpenSSL's default-provider ML-DSA is portable C on every platform.**
- So any speed-up figure is **specific to the CPU and the build's backend**.
  Measure on your target hardware; do not carry an x86_64-AVX2 result over to a
  portable-C or non-supported architecture. The active backend is shown in
  `openssl list -providers -verbose` (the `build info` line) and in the
  benchmark header.

Backend selection at build time:

| `-DMLDSA_NATIVE_BACKEND=` | effect |
|---|---|
| `AUTO` (default) | native asm on x86_64/AArch64, else portable C |
| `NATIVE` | force native asm (errors on unsupported CPUs) |
| `PORTABLE` | force portable C everywhere (apples-to-apples vs default) |
