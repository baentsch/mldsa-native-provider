/*
 * Copyright (c) The mldsa-native-provider authors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Compatibility shims so the provider builds against OpenSSL 3.2-3.4 headers.
 *
 * The provider only uses 3.0-era provider/EVP framework APIs, but a handful of
 * OSSL_PARAM *names* used for ML-DSA were only added to <openssl/core_names.h>
 * in 3.5. They are just fixed strings; define them if the header lacks them.
 * The string values match those used by the OpenSSL 3.5 default provider, so
 * interop is preserved when this provider runs alongside a 3.5 default.
 */

#ifndef MLDSA_NATIVE_COMPAT_H
#define MLDSA_NATIVE_COMPAT_H

#include <openssl/core_names.h>

#ifndef OSSL_PKEY_PARAM_ML_DSA_SEED
# define OSSL_PKEY_PARAM_ML_DSA_SEED "seed"
#endif
#ifndef OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY
# define OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY "encoded-pub-key"
#endif
#ifndef OSSL_SIGNATURE_PARAM_CONTEXT_STRING
# define OSSL_SIGNATURE_PARAM_CONTEXT_STRING "context-string"
#endif
#ifndef OSSL_SIGNATURE_PARAM_DETERMINISTIC
# define OSSL_SIGNATURE_PARAM_DETERMINISTIC "deterministic"
#endif
#ifndef OSSL_SIGNATURE_PARAM_MESSAGE_ENCODING
# define OSSL_SIGNATURE_PARAM_MESSAGE_ENCODING "message-encoding"
#endif
#ifndef OSSL_SIGNATURE_PARAM_MU
# define OSSL_SIGNATURE_PARAM_MU "mu"
#endif
#ifndef OSSL_SIGNATURE_PARAM_TEST_ENTROPY
# define OSSL_SIGNATURE_PARAM_TEST_ENTROPY "test-entropy"
#endif

#endif /* MLDSA_NATIVE_COMPAT_H */
