#include "test_helpers.h"

void test_modexp_adjusted_exponent_gas() {
  EVM_State vm;
  uint8_t *code = nullptr;
  static const char modexp_call_hex[] =
      "6101006000600037600060006101006000600060056103e8f100";

  uint8_t low_exponent_input[256];
  memset(low_exponent_input, 0, sizeof(low_exponent_input));
  low_exponent_input[31] = 64U;
  low_exponent_input[63] = 32U;
  low_exponent_input[95] = 64U;
  low_exponent_input[96U + 63U] = 1U;
  low_exponent_input[192U + 63U] = 97U;

  EVM_Status status =
      execute_hex_with_calldata(modexp_call_hex, low_exponent_input,
                                sizeof(low_exponent_input), 10'000, &vm, &code);
  assert(status == EVM_OK);
  assert_top_u64(&vm, 1U);
  assert(vm.return_data_size == 64U);
  cleanup(&vm, code);

  uint8_t high_exponent_input[256];
  memcpy(high_exponent_input, low_exponent_input, sizeof(high_exponent_input));
  high_exponent_input[160U] = 0x80U;

  status = execute_hex_with_calldata(modexp_call_hex, high_exponent_input,
                                     sizeof(high_exponent_input), 10'000, &vm,
                                     &code);
  assert(status == EVM_OK);
  assert_top_u64(&vm, 0U);
  assert(vm.return_data_size == 0U);
  cleanup(&vm, code);
}
