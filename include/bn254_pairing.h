#pragma once

#include <stddef.h>
#include <stdint.h>

[[nodiscard]] bool bn254_pairing_check(const uint8_t *input, size_t input_size,
                                       bool *out_is_one);
