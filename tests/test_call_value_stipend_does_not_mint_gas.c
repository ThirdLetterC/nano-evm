#include "test_helpers.h"

void test_call_value_stipend_does_not_mint_gas() {
  EVM_State vm;
  uint8_t *code = nullptr;

  init_vm_from_hex("6000600060006000600160116000f15a00", 39'523, &vm, &code);
  vm.address = uint256_from_u64(1U);
  vm.self_balance = uint256_from_u64(2U);

  EVM_Status status = evm_execute(&vm);
  assert(status == EVM_OK);
  assert(vm.gas_remaining == 2'900U);
  assert(stack_depth(&vm.stack) == 2U);

  uint256_t gas_after_call = uint256_zero();
  uint256_t success_flag = uint256_zero();
  uint256_t one_word = uint256_from_u64(1U);
  uint256_t gas_word = uint256_from_u64(2'900U);
  assert(stack_pop(&vm.stack, &gas_after_call) == STACK_OK);
  assert(stack_pop(&vm.stack, &success_flag) == STACK_OK);
  assert(uint256_cmp(&gas_after_call, &gas_word) == 0);
  assert(uint256_cmp(&success_flag, &one_word) == 0);

  cleanup(&vm, code);
}
