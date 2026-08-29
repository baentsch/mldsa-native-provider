#!/usr/bin/env bash
#
# Copyright (c) The mldsa-native-provider authors
# SPDX-License-Identifier: Apache-2.0
#
# ML-DSA performance benchmark: mldsa-native provider vs the OpenSSL default
# provider, using the plain `openssl speed` CLI. This doubles as a worked
# example of selecting the ML-DSA implementation explicitly with -provider /
# -propquery -- the two invocations differ ONLY in the property query:
#
#     # default provider (OpenSSL's cross-platform C ML-DSA)
#     openssl speed -provider default -propquery '?provider=default' ML-DSA-65
#
#     # this provider (mldsa-native)
#     openssl speed -provider mldsanative -provider default \
#                   -propquery '?provider=mldsanative' ML-DSA-65
#
# IMPORTANT - platform dependence of the results:
#   * mldsa-native ships CPU-optimized assembly backends for x86_64 (AVX2) and
#     AArch64; on those CPUs this provider runs the native backend (see the
#     "build info" line printed below). On any other architecture, or when built
#     with -DMLDSA_NATIVE_BACKEND=PORTABLE, it uses portable C.
#   * OpenSSL's default-provider ML-DSA is portable C on every platform.
#   * Therefore the speed-up shown here is specific to THIS machine and THIS
#     build's backend. Re-run on your target hardware; do not extrapolate an
#     x86_64-AVX2 number to, say, a portable-C or 32-bit target.
#
# Exit 0 always on a completed run; 77 (skip) if the default provider has no
# ML-DSA (OpenSSL < 3.5) or the provider cannot be loaded.

set -u

OPENSSL="${OPENSSL:-openssl}"
OPENSSL_LIBPATH="${OPENSSL_LIBPATH:-}"
MODULE_DIR="${MODULE_DIR:-}"
SECONDS_PER="${SECONDS_PER:-3}"
ALGS=("${@:-}")
[ -z "${ALGS[*]}" ] && ALGS=(ML-DSA-44 ML-DSA-65 ML-DSA-87)

[ -n "$OPENSSL_LIBPATH" ] && export LD_LIBRARY_PATH="$OPENSSL_LIBPATH${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
[ -n "$MODULE_DIR" ] && export OPENSSL_MODULES="$MODULE_DIR"

skip() { echo "SKIP: $*"; exit 77; }

"$OPENSSL" list -providers -provider mldsanative >/dev/null 2>&1 \
    || skip "mldsanative provider not loadable (OPENSSL_MODULES=$OPENSSL_MODULES)"
"$OPENSSL" speed -provider default -seconds 1 ML-DSA-44 >/dev/null 2>&1 \
    || skip "default provider has no ML-DSA (needs OpenSSL 3.5+)"

echo "=================================================================="
echo " ML-DSA benchmark: mldsa-native provider vs OpenSSL default"
echo "=================================================================="
echo "OpenSSL : $("$OPENSSL" version)"
echo "Platform: $(uname -s) $(uname -m)"
cpu=""
if command -v lscpu >/dev/null 2>&1; then
    cpu="$(lscpu | sed -n 's/^Model name:[[:space:]]*//p' | head -1)"
fi
if [ -z "$cpu" ] && [ -r /proc/cpuinfo ]; then
    cpu="$(sed -n 's/^model name[[:space:]]*:[[:space:]]*//p' /proc/cpuinfo | head -1)"
fi
echo "CPU     : ${cpu:-unknown}"
echo "Backend : $("$OPENSSL" list -providers -verbose -provider mldsanative 2>/dev/null \
    | sed -n 's/^[[:space:]]*build info:[[:space:]]*//p' | head -1)"
echo "Seconds per measurement: $SECONDS_PER"
echo

# Pull the three ops/sec figures (keygen, sign, verify) from the last line.
rates() {   # $1 = propquery-selected provider args...; $2 = alg
    "$@" 2>/dev/null | awk '/ML-DSA/ {kg=$(NF-2); sg=$(NF-1); vf=$NF} END{print kg, sg, vf}'
}

printf "%-11s %-8s %14s %14s %9s\n" "algorithm" "op" "default/s" "mldsanative/s" "speedup"
printf -- "------------------------------------------------------------------\n"
for alg in "${ALGS[@]}"; do
    read -r d_kg d_sg d_vf < <(rates "$OPENSSL" speed -provider default \
        -propquery '?provider=default' -seconds "$SECONDS_PER" "$alg")
    read -r m_kg m_sg m_vf < <(rates "$OPENSSL" speed -provider mldsanative \
        -provider default -propquery '?provider=mldsanative' \
        -seconds "$SECONDS_PER" "$alg")
    for op in keygen:$d_kg:$m_kg sign:$d_sg:$m_sg verify:$d_vf:$m_vf; do
        name="${op%%:*}"; rest="${op#*:}"; dv="${rest%%:*}"; mv="${rest#*:}"
        sp=$(awk -v a="$mv" -v b="$dv" 'BEGIN{ if(b>0) printf "%.2fx", a/b; else print "n/a" }')
        printf "%-11s %-8s %14s %14s %9s\n" "$alg" "$name" "$dv" "$mv" "$sp"
    done
done
echo
echo "Note: speed-up is specific to this CPU and this build's backend."
exit 0
