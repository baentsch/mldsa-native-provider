#!/usr/bin/env bash
#
# Copyright (c) The mldsa-native-provider authors
# SPDX-License-Identifier: Apache-2.0
#
# Reproduce the minimal-oqs-provider vs mldsa-native-provider size + interop
# experiment. See RESULTS.md for the recorded findings.
#
# This is a local experiment harness, not part of the shipped provider. It
# builds copies of liboqs / oqs-provider / hybrid-provider under $WORK and does
# not modify those source trees. Requires: cmake, ninja, gcc, python3 (+PyYAML),
# and an OpenSSL < 3.5 install (oqs-provider serves ML-DSA only below 3.5).
set -eu

# ---- configuration (override via environment) ----
OSSL="${OSSL:-/home/mib/git/baentsch/hybrid-provider/.local-34}"   # OpenSSL <3.5 prefix
LIBOQS_SRC="${LIBOQS_SRC:-/home/mib/git/baentsch/hybrid-provider/liboqs}"
OQSPROV_SRC="${OQSPROV_SRC:-/home/mib/git/baentsch/hybrid-provider/oqs-provider}"
HYBRID_SRC="${HYBRID_SRC:-/home/mib/git/baentsch/hybrid-provider}"
OURS_SO="${OURS_SO:-/home/mib/git/baentsch/mldsa-native-provider/build-34/mldsanative.so}"
HERE="$(cd "$(dirname "$0")" && pwd)"
WORK="${WORK:-/tmp/oqs-min-exp}"
LIB="$OSSL/lib64"; [ -d "$LIB" ] || LIB="$OSSL/lib"
export LD_LIBRARY_PATH="$LIB"
mkdir -p "$WORK"

sz() { printf "%8d B (%6.1f KiB)" "$(stat -c%s "$1")" "$(python3 -c "print($(stat -c%s "$1")/1024)")"; }

echo "### 1. minimal static liboqs (ML-DSA only)"
cmake -S "$LIBOQS_SRC" -B "$WORK/liboqs" -GNinja \
  -DCMAKE_INSTALL_PREFIX="$WORK/oqs-install" -DBUILD_SHARED_LIBS=OFF \
  -DOQS_BUILD_ONLY_LIB=ON -DOQS_DIST_BUILD=OFF -DOQS_USE_OPENSSL=OFF \
  -DOQS_MINIMAL_BUILD="SIG_ml_dsa_44;SIG_ml_dsa_65;SIG_ml_dsa_87" \
  -DCMAKE_BUILD_TYPE=Release >/dev/null
ninja -C "$WORK/liboqs" install >/dev/null

echo "### 2. oqs-provider, generate.yml reduced to ML-DSA + 4 hybrids"
rm -rf "$WORK/oqsprov-src"; mkdir -p "$WORK/oqsprov-src"
(cd "$OQSPROV_SRC" && tar --exclude=.git --exclude='_build*' --exclude='build*' \
  --exclude=liboqs -cf - .) | (cd "$WORK/oqsprov-src" && tar xf -)
python3 - "$WORK/oqsprov-src/oqs-template/generate.yml" <<'PY'
import sys, yaml
p=sys.argv[1]; c=yaml.safe_load(open(p))
c['kems']=[]
c['sigs']=[f for f in c['sigs'] if f.get('family')=='ML-DSA']
for v in c['sigs'][0]['variants']:
    v['enable']=True     # keep mix_with -> the 4 ML-DSA hybrids
yaml.safe_dump(c, open(p,'w'), sort_keys=False)
PY
(cd "$WORK/oqsprov-src" && LIBOQS_SRC_DIR="$LIBOQS_SRC" python3 oqs-template/generate.py >/dev/null)
cmake -S "$WORK/oqsprov-src" -B "$WORK/oqsprov" -GNinja \
  -Dliboqs_DIR="$WORK/oqs-install/lib/cmake/liboqs" \
  -DOPENSSL_ROOT_DIR="$OSSL" -DOPENSSL_INCLUDE_DIR="$OSSL/include" \
  -DOPENSSL_CRYPTO_LIBRARY="$LIB/libcrypto.so" -DOPENSSL_SSL_LIBRARY="$LIB/libssl.so" \
  -DCMAKE_BUILD_TYPE=Release >/dev/null
ninja -C "$WORK/oqsprov" >/dev/null

echo "### 3. hybrid-provider, composite OFF, tables trimmed to 4 ML-DSA hybrids"
rm -rf "$WORK/hybrid-src"; mkdir -p "$WORK/hybrid-src"
(cd "$HYBRID_SRC" && tar --exclude=.git --exclude='build*' --exclude='.local*' \
  --exclude=openssl --exclude=openssl-34 --exclude=liboqs --exclude=oqs-provider \
  --exclude='.interop' -cf - .) | (cd "$WORK/hybrid-src" && tar xf -)
python3 "$HERE/trim_hybrid_lists.py" "$WORK/hybrid-src/hybrid_prov.h"
cmake -S "$WORK/hybrid-src" -B "$WORK/hybrid" -GNinja \
  -DHYBRID_COMPOSITE=OFF -DBUILD_TESTING=OFF \
  -DOPENSSL_ROOT_DIR="$OSSL" -DOPENSSL_INCLUDE_DIR="$OSSL/include" \
  -DOPENSSL_CRYPTO_LIBRARY="$LIB/libcrypto.so" -DOPENSSL_SSL_LIBRARY="$LIB/libssl.so" >/dev/null
cmake --build "$WORK/hybrid" --target hybrid-provider >/dev/null

echo "### 4. stage modules"
MODS="$WORK/mods"; rm -rf "$MODS"; mkdir -p "$MODS"
ln -sf "$OURS_SO" "$MODS/mldsanative.so"
ln -sf "$WORK/oqsprov/lib/oqsprovider.so" "$MODS/oqsprovider.so"
ln -sf "$WORK/hybrid/hybrid.so" "$MODS/hybrid.so"

echo "### 5. sizes (stripped)"
for m in mldsanative.so oqsprovider.so hybrid.so; do
  strip -s "$MODS/$m" -o "$WORK/$m.stripped" 2>/dev/null || cp "$MODS/$m" "$WORK/$m.stripped"
  printf "  %-16s %s\n" "$m" "$(sz "$WORK/$m.stripped")"
done

echo "### 6. interop + benchmark (OpenSSL $("$OSSL/bin/openssl" version | awk '{print $2}'))"
# One table-driven program covers both plain (RAW-parameter) and hybrid (SPKI
# DER) interop, then --benchmark times sign/verify on each side.
cc -O2 "$HERE/interop.c" -I"$OSSL/include" -L"$LIB" -lcrypto -o "$WORK/interop"
OPENSSL_MODULES="$MODS" "$WORK/interop" --benchmark
