/*
 * Copyright (c) The mldsa-native-provider authors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Multi-level public API for the mldsa-native submodule: include the (pristine)
 * upstream header once per parameter set so mldsa44_*, mldsa65_*, mldsa87_*
 * symbols are all declared. The configuration comes from
 * mldsa_provider_config.h via -DMLD_CONFIG_FILE, leaving the submodule untouched.
 */

#ifndef MLDSA_NATIVE_ALL_H
#define MLDSA_NATIVE_ALL_H

#define MLD_CONFIG_PARAMETER_SET 44
#include <mldsa_native.h>
#undef MLD_CONFIG_PARAMETER_SET
#undef MLD_H

#define MLD_CONFIG_PARAMETER_SET 65
#include <mldsa_native.h>
#undef MLD_CONFIG_PARAMETER_SET
#undef MLD_H

#define MLD_CONFIG_PARAMETER_SET 87
#include <mldsa_native.h>
#undef MLD_CONFIG_PARAMETER_SET
#undef MLD_H

#endif /* MLDSA_NATIVE_ALL_H */
