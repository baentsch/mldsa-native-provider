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
# Reproducing the README performance tables in your own environment:
#   * Point OPENSSL/OPENSSL_LIBPATH at an OpenSSL >= 3.5 install (the default
#     provider only ships ML-DSA from 3.5 on) and MODULE_DIR at a build of this
#     provider against that same OpenSSL, then run this script.
#   * Set FORMAT=md to emit a GitHub-Markdown table (with a platform/version
#     heading) ready to paste into the README; the default FORMAT=text prints
#     the aligned human-readable table.
#   * In CI this runs per platform (x86_64 / aarch64); when $GITHUB_STEP_SUMMARY
#     is set the Markdown table is also appended there, so each runner publishes
#     its own numbers to the job summary.
#
# Optional regression gate:
#   * Set MLDSA_MIN_SPEEDUP to a number (e.g. 2.0) to turn this into a guard: the
#     script then exits non-zero (1) if ANY measured op is slower than that
#     multiple of the default provider. This defends the "much faster than the
#     default provider" claim and catches the native (asm) backend silently
#     regressing to portable C (which would collapse the speed-up toward ~1x).
#     Unset (the default) = informational only, never fails.
#
# Exit codes: 0 = completed (and, if gated, all ops met MLDSA_MIN_SPEEDUP);
#   77 = skip (default provider has no ML-DSA, i.e. OpenSSL < 3.5, or the
#   provider cannot be loaded); 1 = gate enabled and a regression was detected.

set -u

OPENSSL="${OPENSSL:-openssl}"
OPENSSL_LIBPATH="${OPENSSL_LIBPATH:-}"
MODULE_DIR="${MODULE_DIR:-}"
SECONDS_PER="${SECONDS_PER:-3}"
FORMAT="${FORMAT:-text}"          # text | md
ALGS=("${@:-}")
[ -z "${ALGS[*]}" ] && ALGS=(ML-DSA-44 ML-DSA-65 ML-DSA-87)

[ -n "$OPENSSL_LIBPATH" ] && export LD_LIBRARY_PATH="$OPENSSL_LIBPATH${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
[ -n "$MODULE_DIR" ] && export OPENSSL_MODULES="$MODULE_DIR"

skip() { echo "SKIP: $*"; exit 77; }

"$OPENSSL" list -providers -provider mldsanative >/dev/null 2>&1 \
    || skip "mldsanative provider not loadable (OPENSSL_MODULES=$OPENSSL_MODULES)"
"$OPENSSL" speed -provider default -seconds 1 ML-DSA-44 >/dev/null 2>&1 \
    || skip "default provider has no ML-DSA (needs OpenSSL 3.5+)"

# ---- environment identification (shared by both output formats) --------------
ossl_ver="$("$OPENSSL" version | awk '{print $1, $2}')"
platform="$(uname -s) $(uname -m)"
cpu=""
if command -v lscpu >/dev/null 2>&1; then
    cpu="$(lscpu | sed -n 's/^Model name:[[:space:]]*//p' | head -1)"
fi
if [ -z "$cpu" ] && [ -r /proc/cpuinfo ]; then
    cpu="$(sed -n 's/^model name[[:space:]]*:[[:space:]]*//p' /proc/cpuinfo | head -1)"
fi
[ -z "$cpu" ] && cpu="unknown"
backend="$("$OPENSSL" list -providers -verbose -provider mldsanative 2>/dev/null \
    | sed -n 's/^[[:space:]]*build info:[[:space:]]*//p' | head -1)"

# Pull the three ops/sec figures (keygen, sign, verify) from the last line.
rates() {   # $@ = full openssl speed command
    "$@" 2>/dev/null | awk '/ML-DSA/ {kg=$(NF-2); sg=$(NF-1); vf=$NF} END{print kg, sg, vf}'
}

# Collect rows once; render as text and/or markdown afterwards.
# Each row: "alg|op|default_ops|mldsanative_ops|speedup"
rows=()
for alg in "${ALGS[@]}"; do
    read -r d_kg d_sg d_vf < <(rates "$OPENSSL" speed -provider default \
        -propquery '?provider=default' -seconds "$SECONDS_PER" "$alg")
    read -r m_kg m_sg m_vf < <(rates "$OPENSSL" speed -provider mldsanative \
        -provider default -propquery '?provider=mldsanative' \
        -seconds "$SECONDS_PER" "$alg")
    for op in keygen:$d_kg:$m_kg sign:$d_sg:$m_sg verify:$d_vf:$m_vf; do
        name="${op%%:*}"; rest="${op#*:}"; dv="${rest%%:*}"; mv="${rest#*:}"
        sp=$(awk -v a="$mv" -v b="$dv" 'BEGIN{ if(b>0) printf "%.2f", a/b; else print "n/a" }')
        rows+=("$alg|$name|$dv|$mv|$sp")
    done
done

render_text() {
    echo "=================================================================="
    echo " ML-DSA benchmark: mldsa-native provider vs OpenSSL default"
    echo "=================================================================="
    echo "OpenSSL : $("$OPENSSL" version)"
    echo "Platform: $platform"
    echo "CPU     : $cpu"
    echo "Backend : $backend"
    echo "Seconds per measurement: $SECONDS_PER"
    echo
    printf "%-11s %-8s %14s %14s %9s\n" "algorithm" "op" "default/s" "mldsanative/s" "speedup"
    printf -- "------------------------------------------------------------------\n"
    for r in "${rows[@]}"; do
        IFS='|' read -r alg name dv mv sp <<<"$r"
        printf "%-11s %-8s %14s %14s %8sx\n" "$alg" "$name" "$dv" "$mv" "$sp"
    done
    echo
    echo "Note: speed-up is specific to this CPU and this build's backend."
}

render_md() {
    echo "#### $ossl_ver &middot; $platform &middot; ${cpu} &middot; \`$backend\`"
    echo
    echo "| algorithm | op | default (ops/s) | mldsanative (ops/s) | speedup |"
    echo "|---|---|--:|--:|--:|"
    for r in "${rows[@]}"; do
        IFS='|' read -r alg name dv mv sp <<<"$r"
        echo "| $alg | $name | $dv | $mv | ${sp}× |"
    done
    echo
    echo "_Speed-up is specific to this CPU and this build's backend._"
}

case "$FORMAT" in
    md) render_md ;;
    *)  render_text ;;
esac

# In CI, also publish the Markdown table to the job summary so every runner
# (x86_64, aarch64, ...) records its own numbers regardless of FORMAT.
if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
    render_md >> "$GITHUB_STEP_SUMMARY"
fi

# Optional regression gate (see header): only active when MLDSA_MIN_SPEEDUP is
# set. Fails (exit 1) if any op's this-provider ÷ default speed-up is below it.
rc=0
if [ -n "${MLDSA_MIN_SPEEDUP:-}" ]; then
    floor="$MLDSA_MIN_SPEEDUP"
    echo
    echo "Regression gate: requiring speed-up >= ${floor}x vs default on every op."
    for r in "${rows[@]}"; do
        IFS='|' read -r alg name dv mv sp <<<"$r"
        if [ "$sp" = "n/a" ]; then
            echo "  WARN  $alg $name: no default baseline (speed-up n/a), skipped"
            continue
        fi
        if awk -v s="$sp" -v f="$floor" 'BEGIN{exit !(s+0 < f+0)}'; then
            echo "  FAIL  $alg $name: ${sp}x < ${floor}x"
            rc=1
        else
            echo "  ok    $alg $name: ${sp}x"
        fi
    done
    if [ "$rc" -ne 0 ]; then
        echo "REGRESSION: at least one op fell below ${floor}x vs default" \
             "(native backend regressed to portable C?)."
    else
        echo "PASS: all ops >= ${floor}x vs default."
    fi
fi

exit "$rc"
