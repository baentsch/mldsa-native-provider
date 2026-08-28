#!/usr/bin/env bash
#
# Copyright (c) The mldsa-native-provider authors
# SPDX-License-Identifier: Apache-2.0
#
# IETF PQC certificate interoperability test for the mldsa-native provider.
#
# Consumes the ML-DSA artifacts published by many independent implementations at
# https://github.com/IETF-Hackathon/pqc-certificates and, using ONLY our
# provider for the ML-DSA operations, checks that:
#   * each implementation's self-signed ML-DSA trust-anchor certificate verifies
#     (our provider validates their signature and parses their SPKI), and
#   * every private-key form they ship (seed / expandedKey / both) loads, and a
#     signature made with it verifies against the certificate's public key.
#
# Exit codes: 0 = all pass, 1 = a real interop failure, 77 = skipped
# (no network / repo unavailable) so ctest can mark it SKIPPED.
#
# Configuration via environment or flags:
#   OPENSSL           openssl binary               (--openssl)
#   OPENSSL_LIBPATH   prepended to LD_LIBRARY_PATH  (--libpath)
#   MODULE_DIR        OPENSSL_MODULES (provider .so dir) (--module-dir)
#   PQC_CERTS_DIR     existing checkout of pqc-certificates (else shallow-cloned)
#   PQC_CERTS_URL     clone URL (default IETF-Hackathon/pqc-certificates)

set -u

OPENSSL="${OPENSSL:-openssl}"
OPENSSL_LIBPATH="${OPENSSL_LIBPATH:-}"
MODULE_DIR="${MODULE_DIR:-}"
PQC_CERTS_DIR="${PQC_CERTS_DIR:-}"
PQC_CERTS_URL="${PQC_CERTS_URL:-https://github.com/IETF-Hackathon/pqc-certificates.git}"

while [ $# -gt 0 ]; do
    case "$1" in
        --openssl)     OPENSSL="$2"; shift 2 ;;
        --libpath)     OPENSSL_LIBPATH="$2"; shift 2 ;;
        --module-dir)  MODULE_DIR="$2"; shift 2 ;;
        --certs-dir)   PQC_CERTS_DIR="$2"; shift 2 ;;
        *) echo "unknown arg: $1" >&2; exit 2 ;;
    esac
done

[ -n "$OPENSSL_LIBPATH" ] && export LD_LIBRARY_PATH="$OPENSSL_LIBPATH${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
[ -n "$MODULE_DIR" ] && export OPENSSL_MODULES="$MODULE_DIR"

# Our provider must handle the ML-DSA ops; default is loaded for everything else.
PROV=(-provider mldsanative -provider default -propquery "?provider=mldsanative")

skip() { echo "SKIP: $*"; exit 77; }

command -v unzip >/dev/null 2>&1 || skip "unzip not available"
"$OPENSSL" list -providers -provider mldsanative >/dev/null 2>&1 \
    || skip "mldsanative provider not loadable (OPENSSL_MODULES=$OPENSSL_MODULES)"

# Our provider supplies the ML-DSA crypto, but reading/verifying ML-DSA X.509
# certificates relies on libcrypto's own certificate machinery, which only
# understands ML-DSA from OpenSSL 3.5. Skip on older cores.
ver="$("$OPENSSL" version 2>/dev/null | awk '{print $2}')"
vmaj="${ver%%.*}"; vrest="${ver#*.}"; vmin="${vrest%%.*}"
case "$vmaj" in ''|*[!0-9]*) vmaj=0 ;; esac
case "$vmin" in ''|*[!0-9]*) vmin=0 ;; esac
if [ "$vmaj" -lt 3 ] || { [ "$vmaj" -eq 3 ] && [ "$vmin" -lt 5 ]; }; then
    skip "IETF X.509 ML-DSA interop needs OpenSSL 3.5+ (have ${ver:-unknown})"
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

if [ -z "$PQC_CERTS_DIR" ]; then
    echo "Cloning $PQC_CERTS_URL ..."
    if ! git clone --depth 1 "$PQC_CERTS_URL" "$WORK/repo" >/dev/null 2>&1; then
        skip "could not clone pqc-certificates (no network?)"
    fi
    PQC_CERTS_DIR="$WORK/repo"
fi
[ -d "$PQC_CERTS_DIR/providers" ] || skip "no providers/ in $PQC_CERTS_DIR"

MSG="$WORK/msg.txt"
echo "mldsa-native-provider IETF interop probe" > "$MSG"

# Pure ML-DSA parameter sets: level -> last OID arc.
LEVELS=(44 65 87)
ARCS=(17 18 19)

pass=0; fail=0; providers_seen=0

# Verify a self-signed TA cert with our provider; echo its pubkey PEM path.
verify_cert() {   # $1 = ta.der
    local ta="$1" pem="$1.pem" pub="$1.pub.pem"
    "$OPENSSL" x509 -inform DER -in "$ta" -out "$pem" 2>/dev/null || return 1
    "$OPENSSL" verify "${PROV[@]}" -check_ss_sig -CAfile "$pem" "$pem" \
        >/dev/null 2>&1 || return 1
    "$OPENSSL" x509 -in "$pem" -pubkey -noout -out "$pub" 2>/dev/null || return 1
    echo "$pub"
}

# Sign MSG with a private-key DER (our provider) and verify against a pub PEM.
sign_verify_key() {   # $1 = priv der ; $2 = pub pem
    local key="$1" pub="$2" sig="$1.sig"
    "$OPENSSL" pkeyutl "${PROV[@]}" -sign -inkey "$key" -keyform DER \
        -rawin -in "$MSG" -out "$sig" 2>/dev/null || return 1
    "$OPENSSL" pkeyutl -provider mldsanative -provider default \
        -propquery "?provider=mldsanative" -verify -pubin -inkey "$pub" \
        -rawin -in "$MSG" -sigfile "$sig" >/dev/null 2>&1 || return 1
    return 0
}

# Derive a private key's own public key with our provider (round-trip decode).
own_pub() {   # $1 = priv der ; echoes pub pem path
    local key="$1" pub="$1.own.pem"
    "$OPENSSL" pkey "${PROV[@]}" -in "$key" -inform DER -pubout -out "$pub" \
        2>/dev/null || return 1
    echo "$pub"
}

for pdir in "$PQC_CERTS_DIR"/providers/*/; do
    prov="$(basename "$pdir")"
    zip="$(ls "$pdir"artifacts_certs_r*.zip 2>/dev/null | sort -V | tail -1)"
    [ -z "$zip" ] && continue
    out="$WORK/$prov"; mkdir -p "$out"
    unzip -o -q "$zip" -d "$out" 2>/dev/null || continue

    prov_has=0
    for i in 0 1 2; do
        lvl="${LEVELS[$i]}"; arc="${ARCS[$i]}"
        oid="2.16.840.1.101.3.4.3.${arc}"
        # Exact pure-ML-DSA names only (excludes composites like ml-dsa-65-ecdsa).
        ta="$(find "$out" -type f -name "ml-dsa-${lvl}-${oid}_ta.der" 2>/dev/null | head -1)"

        certpub=""
        if [ -n "$ta" ]; then
            prov_has=1
            if certpub="$(verify_cert "$ta")"; then
                pass=$((pass+1)); echo "  ok    $prov  ML-DSA-$lvl  TA cert verified"
            else
                echo "  FAIL  $prov  ML-DSA-$lvl  TA cert verify"; fail=$((fail+1))
                certpub=""
            fi
        fi

        while IFS= read -r key; do
            [ -n "$key" ] || continue
            prov_has=1
            form="$(basename "$key")"; form="${form##*_${oid}_}"
            # Round-trip: our provider decodes the key and its own pub verifies.
            if ownpub="$(own_pub "$key")" && sign_verify_key "$key" "$ownpub"; then
                pass=$((pass+1)); echo "  ok    $prov  ML-DSA-$lvl  key $form (self)"
            else
                echo "  FAIL  $prov  ML-DSA-$lvl  key $form (self)"; fail=$((fail+1))
                continue
            fi
            # If a cert is present, the key must match the published identity.
            if [ -n "$certpub" ]; then
                if sign_verify_key "$key" "$certpub"; then
                    pass=$((pass+1)); echo "  ok    $prov  ML-DSA-$lvl  key $form (vs cert)"
                else
                    echo "  FAIL  $prov  ML-DSA-$lvl  key $form (vs cert)"; fail=$((fail+1))
                fi
            fi
        done < <(find "$out" -type f -name "ml-dsa-${lvl}-${oid}_*priv*.der" 2>/dev/null)
    done
    [ "$prov_has" = 1 ] && providers_seen=$((providers_seen+1))
done

echo
echo "IETF pqc-certificates interop: $providers_seen implementations, $pass checks passed, $fail failed"
[ "$providers_seen" -eq 0 ] && skip "no ML-DSA artifacts found"
[ "$fail" -eq 0 ] || exit 1
exit 0
