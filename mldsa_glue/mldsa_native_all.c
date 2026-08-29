/*
 * Copyright (c) The mldsa-native-provider authors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Single compilation unit bundling all three ML-DSA security levels from the
 * mldsa-native submodule. The upstream monolithic source (mldsa_native.c) is
 * included three times; configuration is supplied out-of-tree via
 * -DMLD_CONFIG_FILE=mldsa_provider_config.h so the submodule stays pristine.
 */

/* Include level-independent code with the first level, keep shared headers. */
#define MLD_CONFIG_MULTILEVEL_WITH_SHARED
#define MLD_CONFIG_MONOBUILD_KEEP_SHARED_HEADERS
#define MLD_CONFIG_PARAMETER_SET 44
#include "mldsa_native.c"
#undef MLD_CONFIG_PARAMETER_SET
#undef MLD_CONFIG_MULTILEVEL_WITH_SHARED

/* Subsequent levels exclude the level-independent code. */
#define MLD_CONFIG_MULTILEVEL_NO_SHARED
#define MLD_CONFIG_PARAMETER_SET 65
#include "mldsa_native.c"
#undef MLD_CONFIG_PARAMETER_SET
#undef MLD_CONFIG_MONOBUILD_KEEP_SHARED_HEADERS

#define MLD_CONFIG_PARAMETER_SET 87
#include "mldsa_native.c"
#undef MLD_CONFIG_PARAMETER_SET
