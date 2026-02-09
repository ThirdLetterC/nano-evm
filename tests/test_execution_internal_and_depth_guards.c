#include "test_helpers.h"

static bool runtime_account_nonce_is(const EVM_State *vm, const uint256_t *addr,
                                     uint64_t expected_nonce) {
  for (size_t i = 0; i < vm->runtime_accounts_count; ++i) {
    if (uint256_cmp(&vm->runtime_accounts[i].address, addr) == 0) {
      return vm->runtime_accounts[i].nonce == expected_nonce;
    }
  }
  return false;
}

void test_execution_internal_and_depth_guards() {
  EVM_State vm;
  uint8_t *code = nullptr;

  init_vm_from_hex("00", 100U, &vm, &code);
  vm.warm_accounts_count = 1U;
  EVM_Status status = evm_execute(&vm);
  assert(status == EVM_ERR_INTERNAL);
  cleanup(&vm, code);

  init_vm_from_hex("00", 100U, &vm, &code);
  vm.warm_slots_count = 1U;
  status = evm_execute(&vm);
  assert(status == EVM_ERR_INTERNAL);
  cleanup(&vm, code);

  init_vm_from_hex("5f5f5f5f5f5f5ff1", 10'000U, &vm, &code);
  vm.call_depth = 1'024U;
  status = evm_execute(&vm);
  assert(status == EVM_OK);
  assert_top_u64(&vm, 0U);
  assert(vm.return_data_size == 0U);
  cleanup(&vm, code);

  init_vm_from_hex("5f5f5ff0", 80'000U, &vm, &code);
  vm.call_depth = 1'024U;
  vm.address = uint256_from_u64(0x55U);
  status = evm_execute(&vm);
  assert(status == EVM_OK);
  assert_top_u64(&vm, 0U);
  assert(!runtime_account_nonce_is(&vm, &vm.address, 1U));
  cleanup(&vm, code);
}
