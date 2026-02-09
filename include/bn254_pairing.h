#ifndef BN254_PAIRING_H
#define BN254_PAIRING_H

#include <stddef.h>
#include <stdint.h>

[[nodiscard]] bool bn254_pairing_check(const uint8_t *input, size_t input_size,
                                       bool *out_is_one);

#endif
