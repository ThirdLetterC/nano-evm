#ifndef UINT256_H
#define UINT256_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
  uint64_t limbs[4];
} uint256_t;

[[nodiscard]] uint256_t uint256_zero();
[[nodiscard]] uint256_t uint256_from_u64(uint64_t value);

[[nodiscard]] bool uint256_is_zero(const uint256_t *value);
[[nodiscard]] int uint256_cmp(const uint256_t *a, const uint256_t *b);
[[nodiscard]] bool uint256_fits_size_t(const uint256_t *value);
[[nodiscard]] size_t uint256_to_size_t(const uint256_t *value);

[[nodiscard]] uint256_t uint256_add(const uint256_t *a, const uint256_t *b);
[[nodiscard]] uint256_t uint256_sub(const uint256_t *a, const uint256_t *b);
[[nodiscard]] uint256_t uint256_mul(const uint256_t *a, const uint256_t *b);
[[nodiscard]] uint256_t uint256_div(const uint256_t *numerator,
                                    const uint256_t *denominator);
[[nodiscard]] uint256_t uint256_sdiv(const uint256_t *numerator,
                                     const uint256_t *denominator);
[[nodiscard]] uint256_t uint256_mod(const uint256_t *numerator,
                                    const uint256_t *denominator);
[[nodiscard]] uint256_t uint256_smod(const uint256_t *numerator,
                                     const uint256_t *denominator);
[[nodiscard]] uint256_t uint256_addmod(const uint256_t *a, const uint256_t *b,
                                       const uint256_t *modulus);
[[nodiscard]] uint256_t uint256_mulmod(const uint256_t *a, const uint256_t *b,
                                       const uint256_t *modulus);
[[nodiscard]] uint256_t uint256_exp(const uint256_t *base,
                                    const uint256_t *exponent);
[[nodiscard]] uint256_t uint256_signextend(const uint256_t *byte_index,
                                           const uint256_t *value);

[[nodiscard]] uint256_t uint256_and(const uint256_t *a, const uint256_t *b);
[[nodiscard]] uint256_t uint256_or(const uint256_t *a, const uint256_t *b);
[[nodiscard]] uint256_t uint256_xor(const uint256_t *a, const uint256_t *b);
[[nodiscard]] uint256_t uint256_not(const uint256_t *value);
[[nodiscard]] uint256_t uint256_byte(const uint256_t *index,
                                     const uint256_t *value);
[[nodiscard]] uint256_t uint256_shl(const uint256_t *shift,
                                    const uint256_t *value);
[[nodiscard]] uint256_t uint256_shr(const uint256_t *shift,
                                    const uint256_t *value);
[[nodiscard]] uint256_t uint256_sar(const uint256_t *shift,
                                    const uint256_t *value);
[[nodiscard]] int uint256_scmp(const uint256_t *a, const uint256_t *b);
[[nodiscard]] uint64_t uint256_significant_bytes(const uint256_t *value);

void uint256_from_be_bytes(uint256_t *out, const uint8_t bytes[32]);
void uint256_to_be_bytes(const uint256_t *value, uint8_t out[32]);

#endif
