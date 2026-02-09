#include "test_helpers.h"

void test_create2_increments_sender_nonce_for_create_addressing() {
  EVM_State vm;
  uint8_t *code = nullptr;

  init_vm_from_hex("5f5f53602a60015f5ff560015f5ff0", 120'000, &vm, &code);
  vm.address = uint256_from_u64(0x99);

  EVM_Status status = evm_execute(&vm);
  assert(status == EVM_OK);
  assert(stack_depth(&vm.stack) == 2);

  uint256_t create_address = uint256_zero();
  uint256_t create2_address = uint256_zero();
  assert(stack_pop(&vm.stack, &create_address) == STACK_OK);
  assert(stack_pop(&vm.stack, &create2_address) == STACK_OK);
  assert(!uint256_is_zero(&create_address));
  assert(!uint256_is_zero(&create2_address));

  uint256_t expected_create_address = derive_create_address_expected(0x99, 1U);
  uint256_t unexpected_create_address =
      derive_create_address_expected(0x99, 0U);
  assert(uint256_cmp(&create_address, &expected_create_address) == 0);
  assert(uint256_cmp(&create_address, &unexpected_create_address) != 0);

  cleanup(&vm, code);
}

