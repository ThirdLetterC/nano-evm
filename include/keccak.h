/* ethash: C/C++ implementation of Ethash, the Ethereum Proof of Work algorithm.
 * Copyright 2018-2019 Pawel Bylica.
 * Licensed under the Apache License, Version 2.0.
 */

#pragma once

#include <stddef.h>
#include <stdint.h>

#include "hash_types.h"

// Provide __has_attribute macro if not defined.
#ifndef __has_attribute
#define __has_attribute(name) 0
#endif

// Provide __has_builtin macro if not defined.
#ifndef __has_builtin
#define __has_builtin(x) 0
#endif

// [[always_inline]]
#if defined(_MSC_VER)
#define ALWAYS_INLINE __forceinline
#elif __has_attribute(always_inline)
#define ALWAYS_INLINE __attribute__((always_inline))
#else
#define ALWAYS_INLINE
#endif

#define noexcept // Ignore noexcept in C code.

[[nodiscard]] union ethash_hash256 ethash_keccak256(const uint8_t *data,
                                                    size_t size);
[[nodiscard]] union ethash_hash256 ethash_keccak256_32(const uint8_t data[32]);
[[nodiscard]] union ethash_hash512 ethash_keccak512(const uint8_t *data,
                                                    size_t size);
[[nodiscard]] union ethash_hash512 ethash_keccak512_64(const uint8_t data[64]);
