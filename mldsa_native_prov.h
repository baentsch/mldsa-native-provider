/*
 * Copyright (c) The mldsa-native-provider authors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Shared declarations for the mldsa-native OpenSSL provider.
 *
 * This provider implements ML-DSA (FIPS 204) signatures ONLY, using the
 * mldsa-native implementation (https://github.com/pq-code-package/mldsa-native)
 * directly -- no delegation to OpenSSL's own ML-DSA or any other intermediate
 * crypto API. No KEM support.
 */

#ifndef MLDSA_NATIVE_PROV_H
#define MLDSA_NATIVE_PROV_H

#include <stddef.h>
#include <stdint.h>

#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/err.h>

/* Fallback OSSL_PARAM name macros for OpenSSL 3.2-3.4 headers. */
#include "mldsa_native_compat.h"

/* mldsa-native (submodule) multi-level public API: mldsa44_/mldsa65_/mldsa87_. */
#include "mldsa_native_all.h"

/* mldsa-native's entropy hook, implemented in mldsa_native_prov.c. */
int randombytes(uint8_t *out, size_t outlen);

#define MLDSANATIVE_PROV_NAME "mldsa-native-provider"
#define MLDSANATIVE_PROV_VERSION "0.1.0"
/* Active mldsa-native backend, injected by CMake (see MLDSA_NATIVE_BACKEND). */
#ifndef MLDSANATIVE_BACKEND_STR
# define MLDSANATIVE_BACKEND_STR "portable C"
#endif
/* Property advertised on every algorithm this provider serves. */
#define MLDSANATIVE_PROPS "provider=mldsanative"

/* Provider context. */
typedef struct prov_mldsa_ctx_st {
    const OSSL_CORE_HANDLE *handle;
    OSSL_LIB_CTX *libctx;   /* child libctx mirroring the parent */
} PROV_MLDSA_CTX;

#define PROV_MLDSA_LIBCTX(pctx) (((PROV_MLDSA_CTX *)(pctx))->libctx)

/*
 * Per-parameter-set description plus function pointers into mldsa-native.
 * Keeps the keymgmt / signature / codec code free of per-level switches.
 */
typedef struct mldsa_params_st {
    int level;               /* 44, 65 or 87 */
    const char *name;        /* "ML-DSA-44" */
    const char *oid;         /* dotted OID string */
    size_t pk_len;
    size_t sk_len;           /* expanded secret key length */
    size_t sig_len;
    int security_bits;
    int security_category;   /* NIST category 2/3/5 */

    int (*keypair_internal)(uint8_t *pk, uint8_t *sk, const uint8_t *seed);
    int (*pk_from_sk)(uint8_t *pk, const uint8_t *sk);
    int (*sign)(uint8_t *sig, const uint8_t *m, size_t mlen,
                const uint8_t *ctx, size_t ctxlen, const uint8_t *sk);
    int (*verify)(const uint8_t *sig, const uint8_t *m, size_t mlen,
                  const uint8_t *ctx, size_t ctxlen, const uint8_t *pk);
    int (*sign_internal)(uint8_t *sig, const uint8_t *m, size_t mlen,
                         const uint8_t *pre, size_t prelen, const uint8_t *rnd,
                         const uint8_t *sk, int externalmu);
    size_t (*prep_prefix)(uint8_t *prefix, const uint8_t *ph, size_t phlen,
                          const uint8_t *ctx, size_t ctxlen, int hashalg);
} MLDSA_PARAMS;

#define MLDSA_SEED_LEN 32
#define MLDSA_RND_LEN  32

/* Seed = 32; matches OpenSSL default provider "seed" import/export. */

/* The ML-DSA key object shared by keymgmt, signature and codecs. */
typedef struct mldsa_key_st {
    OSSL_LIB_CTX *libctx;
    char *propq;
    const MLDSA_PARAMS *params;

    int has_pub;
    int has_priv;
    int has_seed;

    uint8_t *pub;    /* params->pk_len */
    uint8_t *priv;   /* params->sk_len (expanded) */
    uint8_t seed[MLDSA_SEED_LEN];
} MLDSA_KEY;

/* Parameter-set table (defined in mldsa_native_prov.c). */
extern const MLDSA_PARAMS mldsa_params_44;
extern const MLDSA_PARAMS mldsa_params_65;
extern const MLDSA_PARAMS mldsa_params_87;

const MLDSA_PARAMS *mldsa_params_by_name(const char *name);
const MLDSA_PARAMS *mldsa_params_by_oid(const char *oid);
const MLDSA_PARAMS *mldsa_params_by_level(int level);

/* Key helpers (mldsa_native_keymgmt.c). */
MLDSA_KEY *mldsa_key_new(OSSL_LIB_CTX *libctx, const char *propq,
                         const MLDSA_PARAMS *params);
void mldsa_key_free(MLDSA_KEY *key);
MLDSA_KEY *mldsa_key_dup(const MLDSA_KEY *src);
/* Fill pub/priv from the currently-set seed (expects has_seed). */
int mldsa_key_from_seed(MLDSA_KEY *key);
/* Fill pub from the currently-set expanded priv (expects has_priv). */
int mldsa_key_pub_from_priv(MLDSA_KEY *key);
/* Allocate key->priv (params->sk_len) if not yet allocated. */
int mldsa_key_alloc_priv(MLDSA_KEY *key);

/* Dispatch tables. */
extern const OSSL_DISPATCH mldsa44_keymgmt_functions[];
extern const OSSL_DISPATCH mldsa65_keymgmt_functions[];
extern const OSSL_DISPATCH mldsa87_keymgmt_functions[];
extern const OSSL_DISPATCH mldsa_signature_functions[];

/* Encoders (mldsa_native_encoder.c). */
extern const OSSL_DISPATCH mldsa44_to_spki_der_encoder_functions[];
extern const OSSL_DISPATCH mldsa44_to_spki_pem_encoder_functions[];
extern const OSSL_DISPATCH mldsa44_to_pki_der_encoder_functions[];
extern const OSSL_DISPATCH mldsa44_to_pki_pem_encoder_functions[];
extern const OSSL_DISPATCH mldsa65_to_spki_der_encoder_functions[];
extern const OSSL_DISPATCH mldsa65_to_spki_pem_encoder_functions[];
extern const OSSL_DISPATCH mldsa65_to_pki_der_encoder_functions[];
extern const OSSL_DISPATCH mldsa65_to_pki_pem_encoder_functions[];
extern const OSSL_DISPATCH mldsa87_to_spki_der_encoder_functions[];
extern const OSSL_DISPATCH mldsa87_to_spki_pem_encoder_functions[];
extern const OSSL_DISPATCH mldsa87_to_pki_der_encoder_functions[];
extern const OSSL_DISPATCH mldsa87_to_pki_pem_encoder_functions[];

/* Decoders (mldsa_native_decoder.c). */
extern const OSSL_DISPATCH mldsa44_spki_der_to_key_decoder_functions[];
extern const OSSL_DISPATCH mldsa44_pki_der_to_key_decoder_functions[];
extern const OSSL_DISPATCH mldsa65_spki_der_to_key_decoder_functions[];
extern const OSSL_DISPATCH mldsa65_pki_der_to_key_decoder_functions[];
extern const OSSL_DISPATCH mldsa87_spki_der_to_key_decoder_functions[];
extern const OSSL_DISPATCH mldsa87_pki_der_to_key_decoder_functions[];

#endif /* MLDSA_NATIVE_PROV_H */
