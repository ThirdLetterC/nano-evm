#include "test_helpers.h"

static void assert_u256_eq_u64(const uint256_t *value, uint64_t expected) {
  uint256_t expected_word = uint256_from_u64(expected);
  assert(uint256_cmp(value, &expected_word) == 0);
}

void test_uint256_and_stack_helpers() {
  EVM_Stack stack;
  stack_init(&stack);
  assert(stack_depth(&stack) == 0U);

  uint256_t out = uint256_zero();
  assert(stack_pop(&stack, &out) == STACK_UNDERFLOW);
  assert(stack_peek(&stack, &out) == STACK_UNDERFLOW);

  for (size_t i = 0; i < EVM_STACK_MAX_DEPTH; ++i) {
    uint256_t value = uint256_from_u64((uint64_t)i);
    assert(stack_push(&stack, &value) == STACK_OK);
  }
  assert(stack_depth(&stack) == EVM_STACK_MAX_DEPTH);

  uint256_t overflow_value = uint256_from_u64(9'999U);
  assert(stack_push(&stack, &overflow_value) == STACK_OVERFLOW);
  assert(stack_pop(&stack, &out) == STACK_OK);
  assert_u256_eq_u64(&out, (uint64_t)(EVM_STACK_MAX_DEPTH - 1U));

  uint256_t zero = uint256_zero();
  uint256_t one = uint256_from_u64(1U);
  uint256_t index_32 = uint256_from_u64(32U);
  uint256_t shift_256 = uint256_from_u64(256U);

  assert(uint256_significant_bytes(&zero) == 0U);
  assert(uint256_significant_bytes(&one) == 1U);
  assert(uint256_fits_size_t(&one));
  assert(uint256_to_size_t(&one) == 1U);

  uint256_t definitely_big = {{0U, 1U, 0U, 0U}};
  assert(!uint256_fits_size_t(&definitely_big));

  uint256_t byte_result = uint256_byte(&index_32, &one);
  assert(uint256_is_zero(&byte_result));

  uint256_t shl_result = uint256_shl(&shift_256, &one);
  uint256_t shr_result = uint256_shr(&shift_256, &one);
  assert(uint256_is_zero(&shl_result));
  assert(uint256_is_zero(&shr_result));

  uint256_t positive_sar = uint256_sar(&shift_256, &one);
  assert(uint256_is_zero(&positive_sar));

  uint256_t minus_one = uint256_sub(&zero, &one);
  uint256_t negative_sar = uint256_sar(&shift_256, &minus_one);
  for (size_t i = 0; i < 4U; ++i) {
    assert(negative_sar.limbs[i] == UINT64_MAX);
  }

  uint256_t signextend_unchanged = uint256_signextend(&index_32, &minus_one);
  assert(uint256_cmp(&signextend_unchanged, &minus_one) == 0);

  assert(uint256_scmp(&minus_one, &one) < 0);
  assert(uint256_scmp(&one, &minus_one) > 0);

  uint256_t div_zero = uint256_div(&one, &zero);
  uint256_t mod_zero = uint256_mod(&one, &zero);
  uint256_t addmod_zero = uint256_addmod(&one, &one, &zero);
  uint256_t mulmod_zero = uint256_mulmod(&one, &one, &zero);
  assert(uint256_is_zero(&div_zero));
  assert(uint256_is_zero(&mod_zero));
  assert(uint256_is_zero(&addmod_zero));
  assert(uint256_is_zero(&mulmod_zero));

  uint8_t bytes[32] = {0};
  uint8_t roundtrip[32] = {0};
  bytes[0] = 0x11U;
  bytes[15] = 0x22U;
  bytes[31] = 0x33U;

  uint256_t from_bytes = uint256_zero();
  uint256_from_be_bytes(&from_bytes, bytes);
  uint256_to_be_bytes(&from_bytes, roundtrip);
  assert(memcmp(bytes, roundtrip, sizeof(bytes)) == 0);
}
