#include "test_helpers.h"

void test_call_new_account_charge_for_empty_runtime_entry() {
  EVM_State vm;
  uint8_t *code = nullptr;

  init_vm_from_hex("6000600060006000600160116000f100", 20'000, &vm, &code);
  vm.address = uint256_from_u64(1U);
  vm.self_balance = uint256_from_u64(2U);
  vm.runtime_accounts = calloc(1U, sizeof(EVM_RuntimeAccount));
  assert(vm.runtime_accounts != nullptr);
  vm.runtime_accounts_count = 1U;
  vm.runtime_accounts_capacity = 1U;
  vm.runtime_accounts[0].address = uint256_from_u64(0x11U);

  EVM_Status status = evm_execute(&vm);
  assert(status == EVM_ERR_OUT_OF_GAS);

  cleanup(&vm, code);
}
