#!/usr/bin/env bash
#
# Copyright (c) The mldsa-native-provider authors
# SPDX-License-Identifier: Apache-2.0
#
# Performance-regression guard against oqs-provider. Builds a minimal, host-
# optimized oqs-provider (ML-DSA only, so the comparison is apples-to-apples:
# liboqs's ML-DSA *is* mldsa-native) and runs ci/bench_regression.c, which fails
# (non-zero) if this provider is more than MLDSA_BENCH_MAX_SLOWDOWN times slower
# than oqs-provider on keygen or sign at any level. On the optimized platforms
# (x86_64 AVX2, AArch64 NEON) the two should be within a small factor; a large
# gap almost always means our native backend regressed to portable C.
#
# Must run against an OpenSSL < 3.5 install: there oqs-provider actually serves
# ML-DSA (it cedes to the default provider on 3.5+).
#
# Required env:
#   OPENSSL_PREFIX   OpenSSL (< 3.5) install prefix (has bin/ lib{,64}/ include/)
#   OURS_SO          path to this provider's built mldsanative.so (native backend)
# Optional env:
#   LIBOQS_REF       liboqs git ref to pin       (default: 0.12.0)
#   OQSPROV_REF      oqs-provider git ref to pin  (default: 0.8.0)
#   LIBOQS_SRC       use an existing liboqs checkout instead of cloning
#   OQSPROV_SRC      use an existing oqs-provider checkout instead of cloning
#   WORK             scratch dir (default: mktemp)
#   MLDSA_BENCH_MAX_SLOWDOWN / MLDSA_BENCH_SECONDS  passed through to the bench
set -eu

HERE="$(cd "$(dirname "$0")" && pwd)"
: "${OPENSSL_PREFIX:?set OPENSSL_PREFIX to an OpenSSL <3.5 install}"
: "${OURS_SO:?set OURS_SO to the built mldsanative.so}"
LIBOQS_REF="${LIBOQS_REF:-0.12.0}"
OQSPROV_REF="${OQSPROV_REF:-0.8.0}"
WORK="${WORK:-$(mktemp -d)}"
mkdir -p "$WORK"

LIB="$OPENSSL_PREFIX/lib64"; [ -d "$LIB" ] || LIB="$OPENSSL_PREFIX/lib"
export LD_LIBRARY_PATH="$LIB${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"

ver="$("$OPENSSL_PREFIX/bin/openssl" version | awk '{print $2}')"
echo "### OpenSSL: $ver  (oqs-provider serves ML-DSA only below 3.5)"
case "$ver" in
  3.5*|3.6*|3.7*|3.8*|3.9*|4.*) echo "SKIP: need OpenSSL < 3.5"; exit 77 ;;
esac

fetch() {  # $1=url $2=ref $3=dest
  if [ ! -d "$3" ]; then
    git clone --depth 1 --branch "$2" "$1" "$3" 2>/dev/null \
      || { git clone "$1" "$3" && git -C "$3" checkout "$2"; }
  fi
}

echo "### 1. minimal liboqs (ML-DSA only, host-optimized static lib)"
LIBOQS_SRC="${LIBOQS_SRC:-$WORK/liboqs-src}"
fetch https://github.com/open-quantum-safe/liboqs "$LIBOQS_REF" "$LIBOQS_SRC"
cmake -S "$LIBOQS_SRC" -B "$WORK/liboqs" -GNinja \
  -DCMAKE_INSTALL_PREFIX="$WORK/oqs-install" -DBUILD_SHARED_LIBS=OFF \
  -DOQS_BUILD_ONLY_LIB=ON -DOQS_DIST_BUILD=OFF -DOQS_USE_OPENSSL=OFF \
  -DOQS_MINIMAL_BUILD="SIG_ml_dsa_44;SIG_ml_dsa_65;SIG_ml_dsa_87" \
  -DCMAKE_BUILD_TYPE=Release >/dev/null
ninja -C "$WORK/liboqs" install >/dev/null

echo "### 2. oqs-provider against that liboqs"
OQSPROV_SRC="${OQSPROV_SRC:-$WORK/oqsprov-src}"
fetch https://github.com/open-quantum-safe/oqs-provider "$OQSPROV_REF" "$OQSPROV_SRC"
cmake -S "$OQSPROV_SRC" -B "$WORK/oqsprov" -GNinja \
  -Dliboqs_DIR="$WORK/oqs-install/lib/cmake/liboqs" \
  -DOPENSSL_ROOT_DIR="$OPENSSL_PREFIX" -DOPENSSL_INCLUDE_DIR="$OPENSSL_PREFIX/include" \
  -DOPENSSL_CRYPTO_LIBRARY="$LIB/libcrypto.so" -DOPENSSL_SSL_LIBRARY="$LIB/libssl.so" \
  -DCMAKE_BUILD_TYPE=Release >/dev/null
ninja -C "$WORK/oqsprov" >/dev/null
OQS_SO="$(find "$WORK/oqsprov" -name oqsprovider.so | head -1)"
[ -n "$OQS_SO" ] || { echo "oqsprovider.so not built"; exit 1; }

echo "### 3. stage modules"
MODS="$WORK/mods"; mkdir -p "$MODS"
cp "$OURS_SO" "$MODS/mldsanative.so"
cp "$OQS_SO" "$MODS/oqsprovider.so"

echo "### 4. build + run the regression bench"
cc -O2 -Wall "$HERE/bench_regression.c" -I"$OPENSSL_PREFIX/include" \
  -L"$LIB" -lcrypto -o "$WORK/bench_regression"
OPENSSL_MODULES="$MODS" "$WORK/bench_regression"
