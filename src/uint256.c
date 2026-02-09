#include "uint256.h"

#include <limits.h>
#include <stddef.h>

static uint64_t read_be64(const uint8_t *bytes) {
  return ((uint64_t)bytes[0] << 56) | ((uint64_t)bytes[1] << 48) |
         ((uint64_t)bytes[2] << 40) | ((uint64_t)bytes[3] << 32) |
         ((uint64_t)bytes[4] << 24) | ((uint64_t)bytes[5] << 16) |
         ((uint64_t)bytes[6] << 8) | (uint64_t)bytes[7];
}

static void write_be64(uint64_t value, uint8_t *bytes) {
  bytes[0] = (uint8_t)(value >> 56);
  bytes[1] = (uint8_t)(value >> 48);
  bytes[2] = (uint8_t)(value >> 40);
  bytes[3] = (uint8_t)(value >> 32);
  bytes[4] = (uint8_t)(value >> 24);
  bytes[5] = (uint8_t)(value >> 16);
  bytes[6] = (uint8_t)(value >> 8);
  bytes[7] = (uint8_t)value;
}

static void mul_u64_wide(uint64_t lhs, uint64_t rhs, uint64_t *high,
                         uint64_t *low) {
  constexpr uint64_t mask32 = 0xffff'ffffU;

  uint64_t lhs_lo = lhs & mask32;
  uint64_t lhs_hi = lhs >> 32U;
  uint64_t rhs_lo = rhs & mask32;
  uint64_t rhs_hi = rhs >> 32U;

  uint64_t p00 = lhs_lo * rhs_lo;
  uint64_t p01 = lhs_lo * rhs_hi;
  uint64_t p10 = lhs_hi * rhs_lo;
  uint64_t p11 = lhs_hi * rhs_hi;

  uint64_t middle = (p00 >> 32U) + (p01 & mask32) + (p10 & mask32);

  *low = (p00 & mask32) | (middle << 32U);
  *high = p11 + (p01 >> 32U) + (p10 >> 32U) + (middle >> 32U);
}

static int uint256_get_bit(const uint256_t *value, unsigned int bit) {
  if (bit >= 256U) {
    return 0;
  }
  return (int)((value->limbs[bit / 64U] >> (bit % 64U)) & 1ULL);
}

static void uint256_set_bit(uint256_t *value, unsigned int bit) {
  if (bit >= 256U) {
    return;
  }
  value->limbs[bit / 64U] |= 1ULL << (bit % 64U);
}

static void uint256_clear_bit(uint256_t *value, unsigned int bit) {
  if (bit >= 256U) {
    return;
  }
  value->limbs[bit / 64U] &= ~(1ULL << (bit % 64U));
}

static bool uint256_is_negative(const uint256_t *value) {
  return (value->limbs[3] >> 63U) != 0U;
}

static uint256_t uint256_negate(const uint256_t *value) {
  uint256_t zero = uint256_zero();
  return uint256_sub(&zero, value);
}

static uint256_t uint256_abs(const uint256_t *value) {
  return uint256_is_negative(value) ? uint256_negate(value) : *value;
}

static void uint256_shl1(uint256_t *value) {
  uint64_t carry = 0;
  for (size_t i = 0; i < 4; ++i) {
    uint64_t next_carry = value->limbs[i] >> 63;
    value->limbs[i] = (value->limbs[i] << 1) | carry;
    carry = next_carry;
  }
}

static void uint256_divmod(const uint256_t *numerator,
                           const uint256_t *denominator, uint256_t *quotient,
                           uint256_t *remainder) {
  uint256_t q = uint256_zero();
  uint256_t r = uint256_zero();

  if (uint256_is_zero(denominator)) {
    if (quotient != nullptr) {
      *quotient = q;
    }
    if (remainder != nullptr) {
      *remainder = q;
    }
    return;
  }

  // Binary long division over fixed 256-bit words (MSB to LSB).
  for (int bit = 255; bit >= 0; --bit) {
    uint256_shl1(&r);
    r.limbs[0] |= (uint64_t)uint256_get_bit(numerator, (unsigned int)bit);

    if (uint256_cmp(&r, denominator) >= 0) {
      r = uint256_sub(&r, denominator);
      uint256_set_bit(&q, (unsigned int)bit);
    }
  }

  if (quotient != nullptr) {
    *quotient = q;
  }
  if (remainder != nullptr) {
    *remainder = r;
  }
}

static uint256_t uint256_addmod_reduced(const uint256_t *a, const uint256_t *b,
                                        const uint256_t *modulus) {
  // Both inputs are already reduced modulo m, so use one conditional subtract
  // to compute (a + b) mod m without intermediate overflow.
  uint256_t threshold = uint256_sub(modulus, b);
  if (uint256_cmp(a, &threshold) >= 0) {
    return uint256_sub(a, &threshold);
  }
  return uint256_add(a, b);
}

uint256_t uint256_zero() {
  uint256_t out = {{0, 0, 0, 0}};
  return out;
}

uint256_t uint256_from_u64(uint64_t value) {
  uint256_t out = uint256_zero();
  out.limbs[0] = value;
  return out;
}

bool uint256_is_zero(const uint256_t *value) {
  return value->limbs[0] == 0 && value->limbs[1] == 0 && value->limbs[2] == 0 &&
         value->limbs[3] == 0;
}

int uint256_cmp(const uint256_t *a, const uint256_t *b) {
  for (int i = 3; i >= 0; --i) {
    if (a->limbs[i] < b->limbs[i]) {
      return -1;
    }
    if (a->limbs[i] > b->limbs[i]) {
      return 1;
    }
  }
  return 0;
}

bool uint256_fits_size_t(const uint256_t *value) {
#if SIZE_MAX == UINT64_MAX
  return value->limbs[1] == 0 && value->limbs[2] == 0 && value->limbs[3] == 0;
#elif SIZE_MAX == UINT32_MAX
  return value->limbs[1] == 0 && value->limbs[2] == 0 && value->limbs[3] == 0 &&
         (value->limbs[0] >> 32U) == 0;
#else
  uint256_t max = uint256_zero();
  max.limbs[0] = (uint64_t)SIZE_MAX;
  return uint256_cmp(value, &max) <= 0;
#endif
}

size_t uint256_to_size_t(const uint256_t *value) {
  return (size_t)value->limbs[0];
}

uint256_t uint256_add(const uint256_t *a, const uint256_t *b) {
  uint256_t out = uint256_zero();
  uint64_t carry = 0;

  for (size_t i = 0; i < 4; ++i) {
    uint64_t sum = a->limbs[i] + b->limbs[i];
    bool carry_from_sum = sum < a->limbs[i];

    uint64_t sum_with_carry = sum + carry;
    bool carry_from_carry = sum_with_carry < sum;

    out.limbs[i] = sum_with_carry;
    carry = (uint64_t)(carry_from_sum || carry_from_carry);
  }

  return out;
}

uint256_t uint256_sub(const uint256_t *a, const uint256_t *b) {
  uint256_t out = uint256_zero();
  uint64_t borrow = 0;

  for (size_t i = 0; i < 4; ++i) {
    uint64_t diff = a->limbs[i] - b->limbs[i];
    bool borrow_from_sub = a->limbs[i] < b->limbs[i];

    uint64_t diff_with_borrow = diff - borrow;
    bool borrow_from_borrow = diff < borrow;

    out.limbs[i] = diff_with_borrow;
    borrow = (uint64_t)(borrow_from_sub || borrow_from_borrow);
  }

  return out;
}

uint256_t uint256_mul(const uint256_t *a, const uint256_t *b) {
  uint256_t out = uint256_zero();
  // Schoolbook 4x4 limb multiply with carry propagation across 512-bit
  // accumulator; high half is intentionally truncated by EVM semantics.
  uint64_t accum[8] = {0};

  for (size_t i = 0; i < 4; ++i) {
    for (size_t j = 0; j < 4; ++j) {
      size_t k = i + j;
      uint64_t hi = 0;
      uint64_t lo = 0;
      mul_u64_wide(a->limbs[i], b->limbs[j], &hi, &lo);

      uint64_t sum0 = accum[k] + lo;
      uint64_t carry = (sum0 < accum[k]) ? 1U : 0U;
      accum[k] = sum0;

      if (k + 1U < 8U) {
        uint64_t sum1 = accum[k + 1U] + hi;
        uint64_t carry1 = (sum1 < accum[k + 1U]) ? 1U : 0U;
        accum[k + 1U] = sum1;

        uint64_t sum2 = accum[k + 1U] + carry;
        uint64_t carry2 = (sum2 < accum[k + 1U]) ? 1U : 0U;
        accum[k + 1U] = sum2;
        carry = carry1 + carry2;
      }

      size_t idx = k + 2U;
      while (carry != 0U && idx < 8U) {
        uint64_t next = accum[idx] + carry;
        carry = (next < accum[idx]) ? 1U : 0U;
        accum[idx] = next;
        ++idx;
      }
    }
  }

  for (size_t i = 0; i < 4; ++i) {
    out.limbs[i] = accum[i];
  }
  return out;
}

uint256_t uint256_div(const uint256_t *numerator,
                      const uint256_t *denominator) {
  uint256_t quotient = uint256_zero();
  uint256_divmod(numerator, denominator, &quotient, nullptr);
  return quotient;
}

uint256_t uint256_sdiv(const uint256_t *numerator,
                       const uint256_t *denominator) {
  if (uint256_is_zero(denominator)) {
    return uint256_zero();
  }

  bool negate =
      uint256_is_negative(numerator) != uint256_is_negative(denominator);
  uint256_t abs_numerator = uint256_abs(numerator);
  uint256_t abs_denominator = uint256_abs(denominator);
  uint256_t quotient = uint256_div(&abs_numerator, &abs_denominator);
  return negate ? uint256_negate(&quotient) : quotient;
}

uint256_t uint256_mod(const uint256_t *numerator,
                      const uint256_t *denominator) {
  uint256_t remainder = uint256_zero();
  uint256_divmod(numerator, denominator, nullptr, &remainder);
  return remainder;
}

uint256_t uint256_smod(const uint256_t *numerator,
                       const uint256_t *denominator) {
  if (uint256_is_zero(denominator)) {
    return uint256_zero();
  }

  uint256_t abs_numerator = uint256_abs(numerator);
  uint256_t abs_denominator = uint256_abs(denominator);
  uint256_t remainder = uint256_mod(&abs_numerator, &abs_denominator);
  return uint256_is_negative(numerator) ? uint256_negate(&remainder)
                                        : remainder;
}

uint256_t uint256_addmod(const uint256_t *a, const uint256_t *b,
                         const uint256_t *modulus) {
  if (uint256_is_zero(modulus)) {
    return uint256_zero();
  }

  uint256_t a_mod = uint256_mod(a, modulus);
  uint256_t b_mod = uint256_mod(b, modulus);
  return uint256_addmod_reduced(&a_mod, &b_mod, modulus);
}

uint256_t uint256_mulmod(const uint256_t *a, const uint256_t *b,
                         const uint256_t *modulus) {
  if (uint256_is_zero(modulus)) {
    return uint256_zero();
  }

  // Double-and-add in modular space avoids depending on 512-bit temporaries.
  uint256_t result = uint256_zero();
  uint256_t factor = uint256_mod(a, modulus);
  for (unsigned int bit = 0; bit < 256U; ++bit) {
    if (uint256_get_bit(b, bit) != 0) {
      result = uint256_addmod_reduced(&result, &factor, modulus);
    }
    factor = uint256_addmod_reduced(&factor, &factor, modulus);
  }
  return result;
}

uint256_t uint256_exp(const uint256_t *base, const uint256_t *exponent) {
  uint256_t result = uint256_from_u64(1);
  uint256_t factor = *base;

  for (unsigned int bit = 0; bit < 256U; ++bit) {
    if (uint256_get_bit(exponent, bit) != 0) {
      result = uint256_mul(&result, &factor);
    }
    factor = uint256_mul(&factor, &factor);
  }

  return result;
}

uint256_t uint256_signextend(const uint256_t *byte_index,
                             const uint256_t *value) {
  if (byte_index->limbs[1] != 0 || byte_index->limbs[2] != 0 ||
      byte_index->limbs[3] != 0 || byte_index->limbs[0] >= 32U) {
    return *value;
  }

  unsigned int bit_index = (unsigned int)byte_index->limbs[0] * 8U + 7U;
  bool sign_bit_set = uint256_get_bit(value, bit_index) != 0;

  uint256_t out = *value;
  for (unsigned int bit = bit_index + 1U; bit < 256U; ++bit) {
    if (sign_bit_set) {
      uint256_set_bit(&out, bit);
    } else {
      uint256_clear_bit(&out, bit);
    }
  }

  return out;
}

uint256_t uint256_and(const uint256_t *a, const uint256_t *b) {
  uint256_t out = uint256_zero();
  for (size_t i = 0; i < 4; ++i) {
    out.limbs[i] = a->limbs[i] & b->limbs[i];
  }
  return out;
}

uint256_t uint256_or(const uint256_t *a, const uint256_t *b) {
  uint256_t out = uint256_zero();
  for (size_t i = 0; i < 4; ++i) {
    out.limbs[i] = a->limbs[i] | b->limbs[i];
  }
  return out;
}

uint256_t uint256_xor(const uint256_t *a, const uint256_t *b) {
  uint256_t out = uint256_zero();
  for (size_t i = 0; i < 4; ++i) {
    out.limbs[i] = a->limbs[i] ^ b->limbs[i];
  }
  return out;
}

uint256_t uint256_not(const uint256_t *value) {
  uint256_t out = uint256_zero();
  for (size_t i = 0; i < 4; ++i) {
    out.limbs[i] = ~value->limbs[i];
  }
  return out;
}

uint256_t uint256_byte(const uint256_t *index, const uint256_t *value) {
  if (index->limbs[1] != 0 || index->limbs[2] != 0 || index->limbs[3] != 0 ||
      index->limbs[0] >= 32U) {
    return uint256_zero();
  }

  size_t byte_from_msb = (size_t)index->limbs[0];
  size_t bit_offset_from_lsb = (31U - byte_from_msb) * 8U;
  size_t limb_index = bit_offset_from_lsb / 64U;
  size_t bit_shift = bit_offset_from_lsb % 64U;
  uint8_t selected = (uint8_t)((value->limbs[limb_index] >> bit_shift) & 0xffU);

  return uint256_from_u64((uint64_t)selected);
}

uint256_t uint256_shl(const uint256_t *shift, const uint256_t *value) {
  if (shift->limbs[1] != 0 || shift->limbs[2] != 0 || shift->limbs[3] != 0 ||
      shift->limbs[0] >= 256U) {
    return uint256_zero();
  }

  unsigned int shift_value = (unsigned int)shift->limbs[0];
  if (shift_value == 0U) {
    return *value;
  }

  unsigned int word_shift = shift_value / 64U;
  unsigned int bit_shift = shift_value % 64U;

  uint256_t out = uint256_zero();
  for (int i = 3; i >= 0; --i) {
    int src = i - (int)word_shift;
    if (src < 0) {
      continue;
    }

    uint64_t part = value->limbs[src] << bit_shift;
    if (bit_shift != 0U && src > 0) {
      part |= value->limbs[src - 1] >> (64U - bit_shift);
    }
    out.limbs[i] = part;
  }
  return out;
}

uint256_t uint256_shr(const uint256_t *shift, const uint256_t *value) {
  if (shift->limbs[1] != 0 || shift->limbs[2] != 0 || shift->limbs[3] != 0 ||
      shift->limbs[0] >= 256U) {
    return uint256_zero();
  }

  unsigned int shift_value = (unsigned int)shift->limbs[0];
  if (shift_value == 0U) {
    return *value;
  }

  unsigned int word_shift = shift_value / 64U;
  unsigned int bit_shift = shift_value % 64U;

  uint256_t out = uint256_zero();
  for (size_t i = 0; i < 4; ++i) {
    size_t src = i + (size_t)word_shift;
    if (src >= 4U) {
      continue;
    }

    uint64_t part = value->limbs[src] >> bit_shift;
    if (bit_shift != 0U && src + 1U < 4U) {
      part |= value->limbs[src + 1U] << (64U - bit_shift);
    }
    out.limbs[i] = part;
  }
  return out;
}

uint256_t uint256_sar(const uint256_t *shift, const uint256_t *value) {
  bool negative = uint256_is_negative(value);
  if (shift->limbs[1] != 0 || shift->limbs[2] != 0 || shift->limbs[3] != 0 ||
      shift->limbs[0] >= 256U) {
    if (!negative) {
      return uint256_zero();
    }
    uint256_t ones = {{UINT64_MAX, UINT64_MAX, UINT64_MAX, UINT64_MAX}};
    return ones;
  }

  unsigned int shift_value = (unsigned int)shift->limbs[0];
  if (shift_value == 0U) {
    return *value;
  }

  if (!negative) {
    return uint256_shr(shift, value);
  }

  // Arithmetic shift right replicates the sign bit into vacated high bits.
  uint256_t out = uint256_shr(shift, value);
  for (unsigned int i = 0; i < shift_value; ++i) {
    uint256_set_bit(&out, 255U - i);
  }
  return out;
}

int uint256_scmp(const uint256_t *a, const uint256_t *b) {
  bool a_negative = uint256_is_negative(a);
  bool b_negative = uint256_is_negative(b);
  if (a_negative != b_negative) {
    return a_negative ? -1 : 1;
  }
  return uint256_cmp(a, b);
}

uint64_t uint256_significant_bytes(const uint256_t *value) {
  for (int limb_index = 3; limb_index >= 0; --limb_index) {
    uint64_t limb = value->limbs[limb_index];
    if (limb == 0U) {
      continue;
    }
    for (int byte_index = 7; byte_index >= 0; --byte_index) {
      if (((limb >> (byte_index * 8)) & 0xffU) != 0U) {
        return (uint64_t)limb_index * 8U + (uint64_t)byte_index + 1U;
      }
    }
  }
  return 0;
}

void uint256_from_be_bytes(uint256_t *out, const uint8_t bytes[32]) {
  out->limbs[3] = read_be64(&bytes[0]);
  out->limbs[2] = read_be64(&bytes[8]);
  out->limbs[1] = read_be64(&bytes[16]);
  out->limbs[0] = read_be64(&bytes[24]);
}

void uint256_to_be_bytes(const uint256_t *value, uint8_t out[32]) {
  write_be64(value->limbs[3], &out[0]);
  write_be64(value->limbs[2], &out[8]);
  write_be64(value->limbs[1], &out[16]);
  write_be64(value->limbs[0], &out[24]);
}
