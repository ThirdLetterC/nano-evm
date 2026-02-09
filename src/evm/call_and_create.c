#include <stdlib.h>
#include <string.h>

#include <blake2.h>
#include <gmp.h>
#include <secp256k1.h>
#include <secp256k1_recovery.h>

#include "evm/call_and_create_internal.h"

#include "bn254_pairing.h"
#include "keccak.h"

static EVM_Status precompile_fail(EVM_State *vm, bool *out_success) {
  vm->gas_remaining = 0;
  *out_success = false;
  return set_return_data_bytes(vm, nullptr, 0U);
}

static void precompile_read_padded(const uint8_t *input, size_t input_size,
                                   size_t offset, uint8_t *out,
                                   size_t out_size) {
  memset(out, 0, out_size);
  if (offset >= input_size || input == nullptr) {
    return;
  }
  size_t copy_size = input_size - offset;
  if (copy_size > out_size) {
    copy_size = out_size;
  }
  memcpy(out, input + offset, copy_size);
}

static bool precompile_read_size_word(const uint8_t *input, size_t input_size,
                                      size_t offset, size_t *out) {
  uint8_t word[32];
  precompile_read_padded(input, input_size, offset, word, sizeof(word));
  uint256_t value = uint256_zero();
  uint256_from_be_bytes(&value, word);
  if (!uint256_fits_size_t(&value)) {
    return false;
  }
  *out = uint256_to_size_t(&value);
  return true;
}

static uint64_t precompile_be_bit_length(const uint8_t *bytes, size_t size) {
  for (size_t i = 0; i < size; ++i) {
    uint8_t byte = bytes[i];
    if (byte == 0U) {
      continue;
    }

    unsigned int bit_count = 0U;
    while (byte != 0U) {
      byte >>= 1U;
      bit_count += 1U;
    }

#if SIZE_MAX > UINT64_MAX
    if ((size - i - 1U) > (SIZE_MAX / 8U)) {
      return UINT64_MAX;
    }
#endif
    size_t trailing_bytes = size - i - 1U;
    uint64_t trailing_bits = 0U;
    if (!size_to_u64(trailing_bytes, &trailing_bits)) {
      return UINT64_MAX;
    }
    if (mul_u64_overflow(trailing_bits, 8U, &trailing_bits)) {
      return UINT64_MAX;
    }

    uint64_t total = 0U;
    if (add_u64_overflow(trailing_bits, (uint64_t)bit_count, &total)) {
      return UINT64_MAX;
    }
    return total;
  }
  return 0U;
}

static bool precompile_modexp_adjusted_exponent_len(
    const uint8_t *input, size_t input_size, size_t exponent_offset,
    size_t exponent_len, uint64_t *out_adjusted_len) {
  if (out_adjusted_len == nullptr) {
    return false;
  }

  size_t head_size = (exponent_len < 32U) ? exponent_len : 32U;
  uint8_t head[32] = {0};
  if (head_size > 0U) {
    precompile_read_padded(input, input_size, exponent_offset, head, head_size);
  }

  uint64_t head_bits = precompile_be_bit_length(head, head_size);
  if (head_bits == UINT64_MAX) {
    return false;
  }
  uint64_t head_adjusted_len = (head_bits == 0U) ? 0U : (head_bits - 1U);

  if (exponent_len <= 32U) {
    *out_adjusted_len = head_adjusted_len;
    return true;
  }

  size_t tail_bytes = exponent_len - 32U;
  uint64_t tail_bits = 0U;
  if (!size_to_u64(tail_bytes, &tail_bits) ||
      mul_u64_overflow(tail_bits, 8U, &tail_bits) ||
      add_u64_overflow(tail_bits, head_adjusted_len, out_adjusted_len)) {
    return false;
  }
  return true;
}

static bool precompile_linear_cost(size_t data_size, uint64_t base,
                                   uint64_t per_word, uint64_t *out_cost) {
  uint64_t bytes_u64 = 0;
  if (!size_to_u64(data_size, &bytes_u64)) {
    return false;
  }
  uint64_t words = bytes_u64 / 32U;
  if (bytes_u64 % 32U != 0U) {
    if (words == UINT64_MAX) {
      return false;
    }
    words += 1U;
  }

  uint64_t words_cost = 0;
  if (mul_u64_overflow(words, per_word, &words_cost)) {
    return false;
  }
  if (add_u64_overflow(base, words_cost, out_cost)) {
    return false;
  }
  return true;
}

static bool precompile_read_uint256(const uint8_t *input, size_t input_size,
                                    size_t offset, size_t value_size,
                                    uint256_t *out) {
  if (value_size > 32U) {
    return false;
  }

  uint8_t word[32] = {0};
  if (value_size > 0U && offset < input_size && input != nullptr) {
    size_t copy_size = input_size - offset;
    if (copy_size > value_size) {
      copy_size = value_size;
    }
    memcpy(word + (32U - value_size), input + offset, copy_size);
  }

  uint256_from_be_bytes(out, word);
  return true;
}

static bool modexp_size_to_mp_bitcount(size_t bytes, mp_bitcnt_t *out_bits) {
  if ((size_t)(mp_bitcnt_t)bytes != bytes) {
    return false;
  }
  mp_bitcnt_t bytes_as_bits = (mp_bitcnt_t)bytes;
  if (bytes_as_bits > ((mp_bitcnt_t) ~(mp_bitcnt_t)0U) / 8U) {
    return false;
  }
  *out_bits = bytes_as_bits * 8U;
  return true;
}

static bool modexp_import_operand_mpz(mpz_t out, const uint8_t *input,
                                      size_t input_size, size_t operand_offset,
                                      size_t operand_size) {
  mpz_set_ui(out, 0U);

  size_t available = 0U;
  if (input != nullptr && operand_offset < input_size) {
    available = input_size - operand_offset;
    if (available > operand_size) {
      available = operand_size;
    }
  }

  if (available > 0U) {
    mpz_import(out, available, 1, 1, 1, 0, input + operand_offset);
  }

  size_t missing = operand_size - available;
  if (missing > 0U) {
    mp_bitcnt_t shift = 0U;
    if (!modexp_size_to_mp_bitcount(missing, &shift)) {
      return false;
    }
    mpz_mul_2exp(out, out, shift);
  }

  return true;
}

static EVM_Status modexp_set_return_data_mpz(EVM_State *vm, const mpz_t value,
                                             size_t output_size) {
  if (output_size == 0U) {
    return set_return_data_bytes(vm, nullptr, 0U);
  }

  uint8_t *encoded = calloc(output_size, sizeof(uint8_t));
  if (encoded == nullptr) {
    return EVM_ERR_OOM;
  }

  size_t exported_size = 0U;
  uint8_t *exported =
      (uint8_t *)mpz_export(nullptr, &exported_size, 1, 1, 1, 0, value);
  if (exported == nullptr && exported_size != 0U) {
    free(encoded);
    return EVM_ERR_OOM;
  }

  if (exported_size >= output_size) {
    memcpy(encoded, exported + (exported_size - output_size), output_size);
  } else if (exported_size > 0U) {
    memcpy(encoded + (output_size - exported_size), exported, exported_size);
  }

  if (exported != nullptr) {
    void (*gmp_free_func)(void *, size_t) = nullptr;
    mp_get_memory_functions(nullptr, nullptr, &gmp_free_func);
    if (gmp_free_func != nullptr) {
      gmp_free_func(exported, exported_size);
    } else {
      free(exported);
    }
  }
  EVM_Status status = set_return_data_bytes(vm, encoded, output_size);
  free(encoded);
  return status;
}

static bool precompile_modexp_variable_gmp(
    EVM_State *vm, const uint8_t *input, size_t input_size, size_t base_len,
    size_t exponent_len, size_t modulus_len, size_t base_offset,
    size_t exponent_offset, size_t modulus_offset, EVM_Status *out_status) {
  mpz_t base;
  mpz_t exponent;
  mpz_t modulus;
  mpz_t result;
  mpz_init(base);
  mpz_init(exponent);
  mpz_init(modulus);
  mpz_init(result);

  bool imported = modexp_import_operand_mpz(base, input, input_size,
                                            base_offset, base_len) &&
                  modexp_import_operand_mpz(exponent, input, input_size,
                                            exponent_offset, exponent_len) &&
                  modexp_import_operand_mpz(modulus, input, input_size,
                                            modulus_offset, modulus_len);
  if (!imported) {
    mpz_clear(base);
    mpz_clear(exponent);
    mpz_clear(modulus);
    mpz_clear(result);
    return false;
  }

  if (mpz_cmp_ui(modulus, 0U) == 0 || mpz_cmp_ui(modulus, 1U) == 0) {
    *out_status = set_zero_return_data_bytes(vm, modulus_len);
  } else {
    mpz_powm(result, base, exponent, modulus);
    *out_status = modexp_set_return_data_mpz(vm, result, modulus_len);
  }

  mpz_clear(base);
  mpz_clear(exponent);
  mpz_clear(modulus);
  mpz_clear(result);
  return true;
}

static EVM_Status precompile_modexp_variable(
    EVM_State *vm, const uint8_t *input, size_t input_size, size_t base_len,
    size_t exponent_len, size_t modulus_len, size_t base_offset,
    size_t exponent_offset, size_t modulus_offset) {
  EVM_Status gmp_status = EVM_OK;
  if (!precompile_modexp_variable_gmp(
          vm, input, input_size, base_len, exponent_len, modulus_len,
          base_offset, exponent_offset, modulus_offset, &gmp_status)) {
    return EVM_ERR_OOM;
  }
  return gmp_status;
}

static bool uint256_test_bit(const uint256_t *value, unsigned int bit) {
  if (bit >= 256U) {
    return false;
  }
  return ((value->limbs[bit / 64U] >> (bit % 64U)) & 1U) != 0U;
}

typedef struct {
  uint256_t x;
  uint256_t y;
  bool infinity;
} bn254_g1_point_t;

static constexpr uint256_t BN254_PRIME = {
    {0x43e1f593f0000001U, 0x2833e84879b97091U, 0xb85045b68181585dU,
     0x30644e72e131a029U}};
static constexpr uint256_t BN254_PRIME_MINUS_TWO = {
    {0x43e1f593efffffffU, 0x2833e84879b97091U, 0xb85045b68181585dU,
     0x30644e72e131a029U}};

static bn254_g1_point_t bn254_point_infinity() {
  bn254_g1_point_t point = {
      .x = uint256_zero(),
      .y = uint256_zero(),
      .infinity = true,
  };
  return point;
}

static bool bn254_is_field_element(const uint256_t *value) {
  return uint256_cmp(value, &BN254_PRIME) < 0;
}

static uint256_t bn254_field_add(const uint256_t *a, const uint256_t *b) {
  uint256_t sum = uint256_add(a, b);
  if (uint256_cmp(&sum, &BN254_PRIME) >= 0) {
    sum = uint256_sub(&sum, &BN254_PRIME);
  }
  return sum;
}

static uint256_t bn254_field_sub(const uint256_t *a, const uint256_t *b) {
  if (uint256_cmp(a, b) >= 0) {
    return uint256_sub(a, b);
  }
  uint256_t gap = uint256_sub(b, a);
  return uint256_sub(&BN254_PRIME, &gap);
}

static uint256_t bn254_field_mul(const uint256_t *a, const uint256_t *b) {
  return uint256_mulmod(a, b, &BN254_PRIME);
}

static uint256_t bn254_field_pow(const uint256_t *base,
                                 const uint256_t *exponent) {
  uint256_t result = uint256_from_u64(1U);
  uint256_t factor = uint256_mod(base, &BN254_PRIME);

  for (unsigned int bit = 0; bit < 256U; ++bit) {
    if (uint256_test_bit(exponent, bit)) {
      result = bn254_field_mul(&result, &factor);
    }
    factor = bn254_field_mul(&factor, &factor);
  }
  return result;
}

static uint256_t bn254_field_inv(const uint256_t *value) {
  if (uint256_is_zero(value)) {
    return uint256_zero();
  }
  return bn254_field_pow(value, &BN254_PRIME_MINUS_TWO);
}

static uint256_t bn254_curve_rhs(const uint256_t *x) {
  uint256_t x_squared = bn254_field_mul(x, x);
  uint256_t x_cubed = bn254_field_mul(&x_squared, x);
  uint256_t three = uint256_from_u64(3U);
  return bn254_field_add(&x_cubed, &three);
}

static bool bn254_point_is_on_curve(const bn254_g1_point_t *point) {
  if (point->infinity) {
    return true;
  }
  uint256_t lhs = bn254_field_mul(&point->y, &point->y);
  uint256_t rhs = bn254_curve_rhs(&point->x);
  return uint256_cmp(&lhs, &rhs) == 0;
}

static bool bn254_read_g1_point(const uint8_t *input, size_t input_size,
                                size_t offset, bn254_g1_point_t *out_point) {
  uint256_t x = uint256_zero();
  uint256_t y = uint256_zero();
  if (!precompile_read_uint256(input, input_size, offset, 32U, &x) ||
      !precompile_read_uint256(input, input_size, offset + 32U, 32U, &y)) {
    return false;
  }

  out_point->x = x;
  out_point->y = y;
  out_point->infinity = uint256_is_zero(&x) && uint256_is_zero(&y);
  if (out_point->infinity) {
    return true;
  }

  if (!bn254_is_field_element(&out_point->x) ||
      !bn254_is_field_element(&out_point->y)) {
    return false;
  }

  return bn254_point_is_on_curve(out_point);
}

static void bn254_write_g1_point(const bn254_g1_point_t *point,
                                 uint8_t out[64]) {
  memset(out, 0, 64U);
  if (point->infinity) {
    return;
  }
  uint256_to_be_bytes(&point->x, out);
  uint256_to_be_bytes(&point->y, out + 32U);
}

static bn254_g1_point_t bn254_point_add(const bn254_g1_point_t *a,
                                        const bn254_g1_point_t *b) {
  if (a->infinity) {
    return *b;
  }
  if (b->infinity) {
    return *a;
  }

  uint256_t lambda = uint256_zero();
  if (uint256_cmp(&a->x, &b->x) == 0) {
    if (uint256_cmp(&a->y, &b->y) != 0 || uint256_is_zero(&a->y)) {
      return bn254_point_infinity();
    }
    uint256_t x_squared = bn254_field_mul(&a->x, &a->x);
    uint256_t three = uint256_from_u64(3U);
    uint256_t numerator = bn254_field_mul(&x_squared, &three);
    uint256_t two = uint256_from_u64(2U);
    uint256_t denominator = bn254_field_mul(&a->y, &two);
    uint256_t inverse = bn254_field_inv(&denominator);
    if (uint256_is_zero(&inverse)) {
      return bn254_point_infinity();
    }
    lambda = bn254_field_mul(&numerator, &inverse);
  } else {
    uint256_t numerator = bn254_field_sub(&b->y, &a->y);
    uint256_t denominator = bn254_field_sub(&b->x, &a->x);
    uint256_t inverse = bn254_field_inv(&denominator);
    if (uint256_is_zero(&inverse)) {
      return bn254_point_infinity();
    }
    lambda = bn254_field_mul(&numerator, &inverse);
  }

  uint256_t lambda_squared = bn254_field_mul(&lambda, &lambda);
  uint256_t x3 = bn254_field_sub(&lambda_squared, &a->x);
  x3 = bn254_field_sub(&x3, &b->x);

  uint256_t x1_minus_x3 = bn254_field_sub(&a->x, &x3);
  uint256_t y3 = bn254_field_mul(&lambda, &x1_minus_x3);
  y3 = bn254_field_sub(&y3, &a->y);

  bn254_g1_point_t out = {
      .x = x3,
      .y = y3,
      .infinity = false,
  };
  return out;
}

static bn254_g1_point_t bn254_point_mul(const bn254_g1_point_t *point,
                                        const uint256_t *scalar) {
  if (point->infinity || uint256_is_zero(scalar)) {
    return bn254_point_infinity();
  }

  bn254_g1_point_t result = bn254_point_infinity();
  bn254_g1_point_t addend = *point;

  for (unsigned int bit = 0; bit < 256U; ++bit) {
    if (uint256_test_bit(scalar, bit)) {
      result = bn254_point_add(&result, &addend);
    }
    addend = bn254_point_add(&addend, &addend);
  }

  return result;
}

static bool precompile_ecrecover_address(const uint8_t input_words[128],
                                         uint8_t out_address[20]) {
  for (size_t i = 0; i < 31U; ++i) {
    if (input_words[32U + i] != 0U) {
      return false;
    }
  }

  uint8_t recovery_id = input_words[63];
  if (recovery_id != 27U && recovery_id != 28U) {
    return false;
  }
  recovery_id -= 27U;

  secp256k1_context *context =
      secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
  if (context == nullptr) {
    return false;
  }

  uint8_t compact_signature[64];
  memcpy(compact_signature, input_words + 64U, sizeof(compact_signature));

  secp256k1_ecdsa_recoverable_signature signature;
  if (!secp256k1_ecdsa_recoverable_signature_parse_compact(
          context, &signature, compact_signature, (int)recovery_id)) {
    secp256k1_context_destroy(context);
    return false;
  }

  secp256k1_pubkey pubkey;
  if (!secp256k1_ecdsa_recover(context, &pubkey, &signature, input_words)) {
    secp256k1_context_destroy(context);
    return false;
  }

  uint8_t serialized_pubkey[65];
  size_t serialized_size = sizeof(serialized_pubkey);
  bool serialized = secp256k1_ec_pubkey_serialize(
                        context, serialized_pubkey, &serialized_size, &pubkey,
                        SECP256K1_EC_UNCOMPRESSED) != 0 &&
                    serialized_size == sizeof(serialized_pubkey);
  secp256k1_context_destroy(context);
  if (!serialized) {
    return false;
  }

  const union ethash_hash256 hash =
      ethash_keccak256(serialized_pubkey + 1U, 64U);
  memcpy(out_address, hash.bytes + 12U, 20U);
  return true;
}

static uint64_t precompile_load_le_u64(const uint8_t *in) {
  return (uint64_t)in[0] | ((uint64_t)in[1] << 8U) | ((uint64_t)in[2] << 16U) |
         ((uint64_t)in[3] << 24U) | ((uint64_t)in[4] << 32U) |
         ((uint64_t)in[5] << 40U) | ((uint64_t)in[6] << 48U) |
         ((uint64_t)in[7] << 56U);
}

static void precompile_store_le_u64(uint8_t out[8], uint64_t value) {
  out[0] = (uint8_t)value;
  out[1] = (uint8_t)(value >> 8U);
  out[2] = (uint8_t)(value >> 16U);
  out[3] = (uint8_t)(value >> 24U);
  out[4] = (uint8_t)(value >> 32U);
  out[5] = (uint8_t)(value >> 40U);
  out[6] = (uint8_t)(value >> 48U);
  out[7] = (uint8_t)(value >> 56U);
}

static void precompile_blake2f_counter_sub_block(uint64_t *t0, uint64_t *t1) {
  static constexpr uint64_t BLOCK_BYTES = (uint64_t)BLAKE2B_BLOCKBYTES;
  if (*t0 < BLOCK_BYTES) {
    *t1 -= 1U;
  }
  *t0 -= BLOCK_BYTES;
}

static bool precompile_blake2f_libb2(uint32_t rounds, uint64_t h[8],
                                     const uint8_t block[128], uint64_t t0,
                                     uint64_t t1, bool final_block) {
  if (rounds != 12U) {
    return false;
  }

  blake2b_state state;
  if (blake2b_init(&state, BLAKE2B_OUTBYTES) != 0) {
    return false;
  }

  memcpy(state.h, h, sizeof(state.h));
  state.f[0] = 0U;
  state.f[1] = 0U;
  state.last_node = 0U;

  precompile_blake2f_counter_sub_block(&t0, &t1);
  state.t[0] = t0;
  state.t[1] = t1;

  memset(state.buf, 0, sizeof(state.buf));
  memcpy(state.buf, block, BLAKE2B_BLOCKBYTES);
  state.buflen = (uint32_t)BLAKE2B_BLOCKBYTES;

  if (final_block) {
    uint8_t output[BLAKE2B_OUTBYTES];
    if (blake2b_final(&state, output, sizeof(output)) != 0) {
      return false;
    }
    for (size_t i = 0; i < 8U; ++i) {
      h[i] = precompile_load_le_u64(output + (i * 8U));
    }
    return true;
  }

  uint8_t trigger[BLAKE2B_BLOCKBYTES + 1U] = {0};
  if (blake2b_update(&state, trigger, sizeof(trigger)) != 0) {
    return false;
  }
  memcpy(h, state.h, sizeof(state.h));
  return true;
}

static uint64_t precompile_rotr64(uint64_t value, unsigned int shift) {
  return (value >> shift) | (value << (64U - shift));
}

static void blake2f_mix(uint64_t v[16], size_t a, size_t b, size_t c, size_t d,
                        uint64_t x, uint64_t y) {
  v[a] = v[a] + v[b] + x;
  v[d] = precompile_rotr64(v[d] ^ v[a], 32U);
  v[c] = v[c] + v[d];
  v[b] = precompile_rotr64(v[b] ^ v[c], 24U);
  v[a] = v[a] + v[b] + y;
  v[d] = precompile_rotr64(v[d] ^ v[a], 16U);
  v[c] = v[c] + v[d];
  v[b] = precompile_rotr64(v[b] ^ v[c], 63U);
}

static void blake2f_compress(uint32_t rounds, uint64_t h[8],
                             const uint64_t m[16], uint64_t t0, uint64_t t1,
                             bool final_block) {
  static constexpr uint64_t IV[8] = {
      0x6a09e667f3bcc908U, 0xbb67ae8584caa73bU, 0x3c6ef372fe94f82bU,
      0xa54ff53a5f1d36f1U, 0x510e527fade682d1U, 0x9b05688c2b3e6c1fU,
      0x1f83d9abfb41bd6bU, 0x5be0cd19137e2179U,
  };
  static constexpr uint8_t SIGMA[10][16] = {
      {0U, 1U, 2U, 3U, 4U, 5U, 6U, 7U, 8U, 9U, 10U, 11U, 12U, 13U, 14U, 15U},
      {14U, 10U, 4U, 8U, 9U, 15U, 13U, 6U, 1U, 12U, 0U, 2U, 11U, 7U, 5U, 3U},
      {11U, 8U, 12U, 0U, 5U, 2U, 15U, 13U, 10U, 14U, 3U, 6U, 7U, 1U, 9U, 4U},
      {7U, 9U, 3U, 1U, 13U, 12U, 11U, 14U, 2U, 6U, 5U, 10U, 4U, 0U, 15U, 8U},
      {9U, 0U, 5U, 7U, 2U, 4U, 10U, 15U, 14U, 1U, 11U, 12U, 6U, 8U, 3U, 13U},
      {2U, 12U, 6U, 10U, 0U, 11U, 8U, 3U, 4U, 13U, 7U, 5U, 15U, 14U, 1U, 9U},
      {12U, 5U, 1U, 15U, 14U, 13U, 4U, 10U, 0U, 7U, 6U, 3U, 9U, 2U, 8U, 11U},
      {13U, 11U, 7U, 14U, 12U, 1U, 3U, 9U, 5U, 0U, 15U, 4U, 8U, 6U, 2U, 10U},
      {6U, 15U, 14U, 9U, 11U, 3U, 0U, 8U, 12U, 2U, 13U, 7U, 1U, 4U, 10U, 5U},
      {10U, 2U, 8U, 4U, 7U, 6U, 1U, 5U, 15U, 11U, 9U, 14U, 3U, 12U, 13U, 0U},
  };

  uint64_t v[16];
  memcpy(v, h, 8U * sizeof(uint64_t));
  memcpy(v + 8U, IV, 8U * sizeof(uint64_t));
  v[12] ^= t0;
  v[13] ^= t1;
  if (final_block) {
    v[14] = ~v[14];
  }

  for (uint32_t round = 0; round < rounds; ++round) {
    const uint8_t *schedule = SIGMA[round % 10U];
    blake2f_mix(v, 0U, 4U, 8U, 12U, m[schedule[0]], m[schedule[1]]);
    blake2f_mix(v, 1U, 5U, 9U, 13U, m[schedule[2]], m[schedule[3]]);
    blake2f_mix(v, 2U, 6U, 10U, 14U, m[schedule[4]], m[schedule[5]]);
    blake2f_mix(v, 3U, 7U, 11U, 15U, m[schedule[6]], m[schedule[7]]);
    blake2f_mix(v, 0U, 5U, 10U, 15U, m[schedule[8]], m[schedule[9]]);
    blake2f_mix(v, 1U, 6U, 11U, 12U, m[schedule[10]], m[schedule[11]]);
    blake2f_mix(v, 2U, 7U, 8U, 13U, m[schedule[12]], m[schedule[13]]);
    blake2f_mix(v, 3U, 4U, 9U, 14U, m[schedule[14]], m[schedule[15]]);
  }

  for (size_t i = 0; i < 8U; ++i) {
    h[i] ^= v[i] ^ v[i + 8U];
  }
}

static EVM_Status precompile_blake2f(EVM_State *vm, const uint8_t input[213]) {
  uint32_t rounds = load_be_u32(input);
  uint64_t h[8];
  for (size_t i = 0; i < 8U; ++i) {
    h[i] = precompile_load_le_u64(input + 4U + (i * 8U));
  }
  uint64_t t0 = precompile_load_le_u64(input + 196U);
  uint64_t t1 = precompile_load_le_u64(input + 204U);
  bool final_block = input[212] == 1U;

  if (!precompile_blake2f_libb2(rounds, h, input + 68U, t0, t1, final_block)) {
    uint64_t m[16];
    for (size_t i = 0; i < 16U; ++i) {
      m[i] = precompile_load_le_u64(input + 68U + (i * 8U));
    }
    blake2f_compress(rounds, h, m, t0, t1, final_block);
  }

  uint8_t out[64];
  for (size_t i = 0; i < 8U; ++i) {
    precompile_store_le_u64(out + (i * 8U), h[i]);
  }
  return set_return_data_bytes(vm, out, sizeof(out));
}

static EVM_Status execute_precompile(EVM_State *vm, uint8_t id,
                                     const uint8_t *input, size_t input_size,
                                     bool *out_success) {
  *out_success = false;

  uint64_t cost = 0;
  bool has_cost = false;
  if (id == 1U) {
    cost = GAS_PRECOMPILE_ECRECOVER;
    has_cost = true;
  } else if (id == 2U) {
    has_cost = precompile_linear_cost(input_size, GAS_PRECOMPILE_SHA256_BASE,
                                      GAS_PRECOMPILE_SHA256_WORD, &cost);
  } else if (id == 3U) {
    has_cost = precompile_linear_cost(input_size, GAS_PRECOMPILE_RIPEMD160_BASE,
                                      GAS_PRECOMPILE_RIPEMD160_WORD, &cost);
  } else if (id == 4U) {
    has_cost = precompile_linear_cost(input_size, GAS_PRECOMPILE_IDENTITY_BASE,
                                      GAS_PRECOMPILE_IDENTITY_WORD, &cost);
  } else if (id == 5U) {
    size_t base_len = 0;
    size_t exponent_len = 0;
    size_t modulus_len = 0;
    if (!precompile_read_size_word(input, input_size, 0U, &base_len) ||
        !precompile_read_size_word(input, input_size, 32U, &exponent_len) ||
        !precompile_read_size_word(input, input_size, 64U, &modulus_len)) {
      return precompile_fail(vm, out_success);
    }

    size_t max_len = (base_len > modulus_len) ? base_len : modulus_len;
    uint64_t max_len_u64 = 0;
    if (!size_to_u64(max_len, &max_len_u64)) {
      return precompile_fail(vm, out_success);
    }

    uint64_t words8 = max_len_u64 / 8U;
    if (max_len_u64 % 8U != 0U) {
      words8 += 1U;
    }
    uint64_t complexity = 0;
    if (mul_u64_overflow(words8, words8, &complexity)) {
      return precompile_fail(vm, out_success);
    }
    size_t exponent_offset = 0U;
    if (add_size_overflow(96U, base_len, &exponent_offset)) {
      return precompile_fail(vm, out_success);
    }

    uint64_t adjusted_exp_len = 0U;
    if (!precompile_modexp_adjusted_exponent_len(input, input_size,
                                                 exponent_offset, exponent_len,
                                                 &adjusted_exp_len)) {
      return precompile_fail(vm, out_success);
    }
    uint64_t iteration_count = (adjusted_exp_len == 0U) ? 1U : adjusted_exp_len;
    uint64_t tmp = 0;
    if (mul_u64_overflow(complexity, iteration_count, &tmp)) {
      return precompile_fail(vm, out_success);
    }
    cost = tmp / 3U;
    if (cost < GAS_PRECOMPILE_MODEXP_MIN) {
      cost = GAS_PRECOMPILE_MODEXP_MIN;
    }
    has_cost = true;
  } else if (id == 6U) {
    cost = GAS_PRECOMPILE_BN256ADD;
    has_cost = true;
  } else if (id == 7U) {
    cost = GAS_PRECOMPILE_BN256MUL;
    has_cost = true;
  } else if (id == 8U) {
    if (input_size % 192U != 0U) {
      return precompile_fail(vm, out_success);
    }
    uint64_t pairs = 0;
    if (!size_to_u64(input_size / 192U, &pairs)) {
      return precompile_fail(vm, out_success);
    }
    uint64_t pair_cost = 0;
    if (mul_u64_overflow(pairs, GAS_PRECOMPILE_BN256PAIRING_PER_PAIR,
                         &pair_cost) ||
        add_u64_overflow(GAS_PRECOMPILE_BN256PAIRING_BASE, pair_cost, &cost)) {
      return precompile_fail(vm, out_success);
    }
    has_cost = true;
  } else if (id == 9U) {
    if (input_size != 213U || input == nullptr) {
      return precompile_fail(vm, out_success);
    }
    cost = (uint64_t)load_be_u32(input);
    has_cost = true;
  }

  if (!has_cost) {
    return precompile_fail(vm, out_success);
  }
  if (!precompile_try_charge_gas(vm, cost)) {
    return set_return_data_bytes(vm, nullptr, 0U);
  }

  EVM_Status status = EVM_OK;
  if (id == 1U) {
    uint8_t padded_input[128];
    precompile_read_padded(input, input_size, 0U, padded_input,
                           sizeof(padded_input));

    uint8_t out[32] = {0};
    uint8_t recovered_address[20];
    if (precompile_ecrecover_address(padded_input, recovered_address)) {
      memcpy(out + 12U, recovered_address, sizeof(recovered_address));
    }
    status = set_return_data_bytes(vm, out, sizeof(out));
  } else if (id == 2U) {
    uint8_t digest[32];
    sha256_hash(input, input_size, digest);
    status = set_return_data_bytes(vm, digest, sizeof(digest));
  } else if (id == 3U) {
    uint8_t digest20[20];
    uint8_t digest32[32] = {0};
    ripemd160_hash(input, input_size, digest20);
    memcpy(digest32 + 12U, digest20, sizeof(digest20));
    status = set_return_data_bytes(vm, digest32, sizeof(digest32));
  } else if (id == 4U) {
    status = set_return_data_bytes(vm, input, input_size);
  } else if (id == 5U) {
    size_t base_len = 0;
    size_t exponent_len = 0;
    size_t modulus_len = 0;
    if (!precompile_read_size_word(input, input_size, 0U, &base_len) ||
        !precompile_read_size_word(input, input_size, 32U, &exponent_len) ||
        !precompile_read_size_word(input, input_size, 64U, &modulus_len)) {
      return precompile_fail(vm, out_success);
    }

    if (modulus_len == 0U) {
      status = set_return_data_bytes(vm, nullptr, 0U);
    } else {
      size_t base_offset = 96U;
      size_t exponent_offset = 0;
      size_t modulus_offset = 0;
      if (add_size_overflow(base_offset, base_len, &exponent_offset) ||
          add_size_overflow(exponent_offset, exponent_len, &modulus_offset)) {
        return precompile_fail(vm, out_success);
      }

      status = precompile_modexp_variable(
          vm, input, input_size, base_len, exponent_len, modulus_len,
          base_offset, exponent_offset, modulus_offset);
    }
  } else if (id == 6U) {
    bn254_g1_point_t point_a = bn254_point_infinity();
    bn254_g1_point_t point_b = bn254_point_infinity();
    if (!bn254_read_g1_point(input, input_size, 0U, &point_a) ||
        !bn254_read_g1_point(input, input_size, 64U, &point_b)) {
      return precompile_fail(vm, out_success);
    }
    bn254_g1_point_t sum = bn254_point_add(&point_a, &point_b);
    uint8_t out[64];
    bn254_write_g1_point(&sum, out);
    status = set_return_data_bytes(vm, out, sizeof(out));
  } else if (id == 7U) {
    bn254_g1_point_t point = bn254_point_infinity();
    if (!bn254_read_g1_point(input, input_size, 0U, &point)) {
      return precompile_fail(vm, out_success);
    }

    uint256_t scalar = uint256_zero();
    if (!precompile_read_uint256(input, input_size, 64U, 32U, &scalar)) {
      return precompile_fail(vm, out_success);
    }
    bn254_g1_point_t product = bn254_point_mul(&point, &scalar);
    uint8_t out[64];
    bn254_write_g1_point(&product, out);
    status = set_return_data_bytes(vm, out, sizeof(out));
  } else if (id == 8U) {
    bool pairing_is_one = false;
    if (!bn254_pairing_check(input, input_size, &pairing_is_one)) {
      return precompile_fail(vm, out_success);
    }

    uint8_t out[32] = {0};
    if (pairing_is_one) {
      out[31] = 1U;
    }
    status = set_return_data_bytes(vm, out, sizeof(out));
  } else {
    if (input[212] > 1U) {
      return precompile_fail(vm, out_success);
    }
    status = precompile_blake2f(vm, input);
  }

  if (status != EVM_OK) {
    return status;
  }
  *out_success = true;
  return EVM_OK;
}

static void uint256_to_address20(const uint256_t *value, uint8_t out[20]) {
  uint8_t full_word[32];
  uint256_to_be_bytes(value, full_word);
  memcpy(out, full_word + 12U, 20U);
}

static uint256_t hash_to_address(const union ethash_hash256 *hash) {
  uint8_t address_word[32] = {0};
  memcpy(address_word + 12U, hash->bytes + 12U, 20U);
  uint256_t address = uint256_zero();
  uint256_from_be_bytes(&address, address_word);
  return address;
}

static size_t rlp_encode_nonce(uint64_t nonce, uint8_t out[9]) {
  if (nonce == 0U) {
    out[0] = 0x80U;
    return 1U;
  }

  uint8_t be[8];
  for (size_t i = 0; i < 8U; ++i) {
    be[i] = (uint8_t)(nonce >> ((7U - i) * 8U));
  }

  size_t first_nonzero = 0;
  while (first_nonzero < 7U && be[first_nonzero] == 0U) {
    first_nonzero += 1U;
  }

  size_t payload_size = 8U - first_nonzero;
  if (payload_size == 1U && be[first_nonzero] <= 0x7fU) {
    out[0] = be[first_nonzero];
    return 1U;
  }

  out[0] = (uint8_t)(0x80U + payload_size);
  memcpy(out + 1U, be + first_nonzero, payload_size);
  return payload_size + 1U;
}

static uint256_t derive_create_address(const EVM_State *vm,
                                       uint64_t create_nonce) {
  uint8_t encoded_nonce[9];
  size_t nonce_size = rlp_encode_nonce(create_nonce, encoded_nonce);

  // CREATE address = keccak256(rlp([sender, nonce]))[12:].
  uint8_t payload[1 + 1 + 20 + 9];
  payload[0] = (uint8_t)(0xc0U + 1U + 20U + nonce_size);
  payload[1] = 0x94U;
  uint256_to_address20(&vm->address, payload + 2U);
  memcpy(payload + 22U, encoded_nonce, nonce_size);

  const union ethash_hash256 hash = ethash_keccak256(payload, 22U + nonce_size);
  return hash_to_address(&hash);
}

static uint256_t derive_create2_address(const EVM_State *vm,
                                        const uint256_t *salt,
                                        const uint8_t init_code_hash[32]) {
  // CREATE2 address = keccak256(0xff || sender || salt || init_code_hash)[12:].
  uint8_t payload[1 + 20 + 32 + 32];
  memset(payload, 0, sizeof(payload));
  payload[0] = 0xffU;
  uint256_to_address20(&vm->address, payload + 1U);

  uint8_t salt_word[32];
  uint256_to_be_bytes(salt, salt_word);
  memcpy(payload + 21U, salt_word, 32U);
  memcpy(payload + 53U, init_code_hash, 32U);

  const union ethash_hash256 hash = ethash_keccak256(payload, sizeof(payload));
  return hash_to_address(&hash);
}

static void inherit_child_context(EVM_State *child, const EVM_State *parent) {
  child->origin = parent->origin;
  child->refund_counter = parent->refund_counter;
  child->gas_price = parent->gas_price;
  child->coinbase = parent->coinbase;
  child->timestamp = parent->timestamp;
  child->block_number = parent->block_number;
  child->prev_randao = parent->prev_randao;
  child->block_gas_limit = parent->block_gas_limit;
  child->chain_id = parent->chain_id;
  child->base_fee = parent->base_fee;
  child->blob_base_fee = parent->blob_base_fee;
  child->blob_hashes = parent->blob_hashes;
  child->blob_hashes_count = parent->blob_hashes_count;
  child->external_accounts = parent->external_accounts;
  child->external_accounts_count = parent->external_accounts_count;
  child->block_hashes = parent->block_hashes;
  child->block_hashes_count = parent->block_hashes_count;
  child->is_static_context = parent->is_static_context;
  child->call_depth = parent->call_depth + 1U;
}

static bool is_child_recoverable_failure(EVM_Status status) {
  switch (status) {
  case EVM_ERR_STACK_OVERFLOW:
  case EVM_ERR_STACK_UNDERFLOW:
  case EVM_ERR_INVALID_OPCODE:
  case EVM_ERR_INVALID_BYTECODE:
  case EVM_ERR_OUT_OF_GAS:
  case EVM_ERR_WRITE_PROTECTION:
  case EVM_ERR_REVERT:
    return true;
  default:
    return false;
  }
}

static EVM_Status return_child_gas(EVM_State *vm,
                                   uint64_t child_gas_remaining) {
  if (add_u64_overflow(vm->gas_remaining, child_gas_remaining,
                       &vm->gas_remaining)) {
    return EVM_ERR_INTERNAL;
  }
  return EVM_OK;
}

EVM_Status execute_message_call(EVM_State *vm, uint8_t opcode,
                                       uint64_t gas_forwarded,
                                       const uint256_t *target,
                                       const uint256_t *value,
                                       const uint8_t *input_data,
                                       size_t input_size, bool *out_success) {
  // Recoverable child failures return success=0; only internal faults bubble.
  *out_success = false;
  int64_t parent_refund_counter = vm->refund_counter;
  if (vm->call_depth >= EVM_MAX_CALL_DEPTH) {
    EVM_Status status = set_return_data_bytes(vm, nullptr, 0U);
    if (status != EVM_OK) {
      return status;
    }
    return return_child_gas(vm, gas_forwarded);
  }
  uint8_t precompile_id = 0;
  bool is_precompile = is_precompile_address(target, &precompile_id);

  const uint8_t *callee_code = nullptr;
  size_t callee_code_size = 0;
  (void)account_code_get(vm, target, &callee_code, &callee_code_size, nullptr);
  if (callee_code_size > 0U && callee_code == nullptr) {
    return EVM_ERR_INTERNAL;
  }

  // Persist parent frame first, then fork child world state from snapshots.
  EVM_Status status = sync_current_account_runtime_state(vm);
  if (status != EVM_OK) {
    return status;
  }

  EVM_State child;
  status = evm_init(&child, callee_code, callee_code_size, gas_forwarded);
  if (status != EVM_OK) {
    return status;
  }

  inherit_child_context(&child, vm);
  child.call_data = input_data;
  child.call_data_size = input_size;

  if (opcode == OPCODE_CALL) {
    child.address = *target;
    child.caller = vm->address;
    child.call_value = (value == nullptr) ? uint256_zero() : *value;
  } else if (opcode == OPCODE_CALLCODE) {
    child.address = vm->address;
    child.caller = vm->address;
    child.call_value = (value == nullptr) ? uint256_zero() : *value;
  } else if (opcode == OPCODE_DELEGATECALL) {
    child.address = vm->address;
    child.caller = vm->caller;
    child.call_value = vm->call_value;
  } else {
    child.address = *target;
    child.caller = vm->address;
    child.call_value = uint256_zero();
    child.is_static_context = true;
  }

  status = runtime_accounts_clone(&child, vm);
  if (status != EVM_OK) {
    evm_destroy(&child);
    return status;
  }
  status = warm_slots_clone(&child, vm);
  if (status != EVM_OK) {
    evm_destroy(&child);
    return status;
  }
  status = warm_accounts_clone(&child, vm);
  if (status != EVM_OK) {
    evm_destroy(&child);
    return status;
  }

  if (opcode == OPCODE_CALL && value != nullptr && !uint256_is_zero(value)) {
    status = account_transfer(&child, &vm->address, target, value);
    if (status != EVM_OK) {
      evm_destroy(&child);
      return status;
    }
  }

  status = runtime_account_load_frame_state(&child, &child.address);
  if (status != EVM_OK) {
    evm_destroy(&child);
    return status;
  }
  child.self_balance = account_balance_get(&child, &child.address);

  EVM_Status child_status = EVM_OK;
  if (is_precompile) {
    bool precompile_success = false;
    status = execute_precompile(&child, precompile_id, input_data, input_size,
                                &precompile_success);
    if (status != EVM_OK) {
      evm_destroy(&child);
      return status;
    }
    child_status = precompile_success ? EVM_OK : EVM_ERR_OUT_OF_GAS;
  } else {
    child_status = evm_execute(&child);
  }

  if (child_status == EVM_OK) {
    vm->refund_counter = child.refund_counter;
  } else {
    vm->refund_counter = parent_refund_counter;
  }

  // Warm sets and gas are transaction-scoped, so they always flow back.
  warm_slots_commit_from_child(vm, &child);
  warm_accounts_commit_from_child(vm, &child);
  status = return_child_gas(vm, child.gas_remaining);
  if (status == EVM_OK) {
    status =
        set_return_data_bytes(vm, child.return_data, child.return_data_size);
  }

  bool call_succeeded = false;
  if (child_status == EVM_OK) {
    // Commit child account/log changes only on successful execution.
    call_succeeded = true;
    if (status == EVM_OK) {
      status = runtime_account_store_frame_state(&child, &child.address);
    }
    if (status == EVM_OK) {
      status = merge_child_logs(vm, &child);
    }
    if (status == EVM_OK) {
      runtime_accounts_commit_from_child(vm, &child);
      status = sync_frame_from_current_account(vm);
    }
  } else if (!is_child_recoverable_failure(child_status) && status == EVM_OK) {
    // Internal consistency failures are fatal for the parent frame too.
    status = child_status;
  }

  evm_destroy(&child);
  if (status != EVM_OK) {
    return status;
  }

  *out_success = call_succeeded;
  return EVM_OK;
}

EVM_Status
execute_create(EVM_State *vm, uint8_t opcode, uint64_t gas_forwarded,
               uint64_t create_nonce, const uint8_t *init_code,
               size_t init_code_size, const uint256_t *endowment,
               const uint256_t *salt, uint256_t *out_address) {
  // Same commit/rollback model as CALL, but return value is created address.
  *out_address = uint256_zero();
  int64_t parent_refund_counter = vm->refund_counter;
  if (vm->call_depth >= EVM_MAX_CALL_DEPTH) {
    EVM_Status status = set_return_data_bytes(vm, nullptr, 0U);
    if (status != EVM_OK) {
      return status;
    }
    return return_child_gas(vm, gas_forwarded);
  }

  if (init_code_size > MAX_INITCODE_SIZE) {
    EVM_Status status = set_return_data_bytes(vm, nullptr, 0U);
    if (status != EVM_OK) {
      return status;
    }
    return return_child_gas(vm, gas_forwarded);
  }

  if (init_code_size > 0U && init_code == nullptr) {
    return EVM_ERR_INTERNAL;
  }

  const union ethash_hash256 init_hash =
      ethash_keccak256(init_code, init_code_size);
  uint256_t created_address = uint256_zero();
  if (opcode == OPCODE_CREATE2) {
    created_address = derive_create2_address(vm, salt, init_hash.bytes);
  } else {
    created_address = derive_create_address(vm, create_nonce);
  }

  EVM_RuntimeAccount existing_account;
  bool account_exists =
      runtime_account_read(vm, &created_address, &existing_account);
  if (account_exists &&
      (existing_account.nonce != 0U || existing_account.code_size > 0U)) {
    EVM_Status status = set_return_data_bytes(vm, nullptr, 0U);
    if (status != EVM_OK) {
      return status;
    }
    return return_child_gas(vm, gas_forwarded);
  }

  EVM_Status status = sync_current_account_runtime_state(vm);
  if (status != EVM_OK) {
    return status;
  }

  EVM_State child;
  status = evm_init(&child, init_code, init_code_size, gas_forwarded);
  if (status != EVM_OK) {
    return status;
  }

  inherit_child_context(&child, vm);
  child.call_data = nullptr;
  child.call_data_size = 0;
  child.address = created_address;
  child.caller = vm->address;
  child.call_value = *endowment;

  status = runtime_accounts_clone(&child, vm);
  if (status != EVM_OK) {
    evm_destroy(&child);
    return status;
  }
  status = warm_slots_clone(&child, vm);
  if (status != EVM_OK) {
    evm_destroy(&child);
    return status;
  }
  status = warm_accounts_clone(&child, vm);
  if (status != EVM_OK) {
    evm_destroy(&child);
    return status;
  }

  status = account_transfer(&child, &vm->address, &created_address, endowment);
  if (status != EVM_OK) {
    evm_destroy(&child);
    return status;
  }

  status = runtime_account_load_frame_state(&child, &child.address);
  if (status != EVM_OK) {
    evm_destroy(&child);
    return status;
  }
  child.self_balance = account_balance_get(&child, &child.address);

  EVM_Status child_status = evm_execute(&child);
  if (child_status == EVM_OK) {
    EVM_Status deposit_status =
        maybe_charge_code_deposit_gas(&child, child.return_data_size);
    if (deposit_status != EVM_OK) {
      child_status = EVM_ERR_OUT_OF_GAS;
      child.gas_remaining = 0;
      EVM_Status clear_status = set_return_data_bytes(&child, nullptr, 0U);
      if (clear_status != EVM_OK) {
        evm_destroy(&child);
        return clear_status;
      }
    }
  }

  if (child_status == EVM_OK) {
    vm->refund_counter = child.refund_counter;
  } else {
    vm->refund_counter = parent_refund_counter;
  }

  warm_slots_commit_from_child(vm, &child);
  warm_accounts_commit_from_child(vm, &child);
  status = return_child_gas(vm, child.gas_remaining);
  if (status == EVM_OK) {
    status =
        set_return_data_bytes(vm, child.return_data, child.return_data_size);
  }

  if (child_status == EVM_OK) {
    if (status == EVM_OK) {
      status = runtime_account_store_frame_state(&child, &child.address);
    }
    if (status == EVM_OK) {
      status =
          account_deploy_contract(&child, &created_address, child.return_data,
                                  child.return_data_size, &child.self_balance);
    }
    if (status == EVM_OK) {
      status = merge_child_logs(vm, &child);
    }
    if (status == EVM_OK) {
      runtime_accounts_commit_from_child(vm, &child);
      status = sync_frame_from_current_account(vm);
    }
    if (status == EVM_OK) {
      *out_address = created_address;
    }
  } else if (!is_child_recoverable_failure(child_status) && status == EVM_OK) {
    status = child_status;
  }

  evm_destroy(&child);
  return status;
}
