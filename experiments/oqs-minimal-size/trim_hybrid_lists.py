#!/usr/bin/env python3
# Copyright (c) The mldsa-native-provider authors
# SPDX-License-Identifier: Apache-2.0
#
# Trim hybrid-provider's X-macro algorithm tables in hybrid_prov.h to exactly
# the four ML-DSA concatenation hybrids and no KEM hybrids, so its binary can be
# compared apples-to-apples against a minimal ML-DSA-only oqs-provider.
import sys

SIG4 = r'''#define HYBRID_SIG_LIST(X)                                                    \
  X(p256_mldsa44,   "p256_mldsa44",   "EC",  "P-256", "MLDSA44", 2,           \
      "1.3.9999.7.5", "P-256+ML-DSA-44", 0xff06)                              \
  X(rsa3072_mldsa44,"rsa3072_mldsa44","RSA", NULL,    "MLDSA44", 2,           \
      "1.3.9999.7.6", "RSA3072+ML-DSA-44", 0xff07)                            \
  X(p384_mldsa65,   "p384_mldsa65",   "EC",  "P-384", "MLDSA65", 3,           \
      "1.3.9999.7.7", "P-384+ML-DSA-65", 0xff08)                              \
  X(p521_mldsa87,   "p521_mldsa87",   "EC",  "P-521", "MLDSA87", 5,           \
      "1.3.9999.7.8", "P-521+ML-DSA-87", 0xff09)'''


def block_end(lines, i):
    j = i
    while j < len(lines) and lines[j].rstrip().endswith('\\'):
        j += 1
    return j


def main(path):
    lines = open(path).read().split('\n')
    out, i = [], 0
    while i < len(lines):
        s = lines[i].lstrip()
        if s.startswith('#define HYBRID_KEM_LIST(X)'):
            out.append('#define HYBRID_KEM_LIST(X)')      # no KEM hybrids
            i = block_end(lines, i) + 1
            continue
        if s.startswith('#define HYBRID_SIG_LIST(X)'):
            out.append(SIG4)                              # only the 4 ML-DSA hybrids
            i = block_end(lines, i) + 1
            continue
        out.append(lines[i])
        i += 1
    open(path, 'w').write('\n'.join(out))
    print(f"trimmed {path}: KEM hybrids=0, SIG hybrids=4 (ML-DSA only)")


if __name__ == '__main__':
    main(sys.argv[1])
