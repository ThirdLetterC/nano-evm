#include "test_helpers.h"

void test_memory_expansion_helper_cost() {
  EVM_State vm;
  EVM_Status status = evm_init(&vm, nullptr, 0, 2);
  assert(status == EVM_OK);

  status = evm_memory_ensure(&vm, 1);
  assert(status == EVM_ERR_OUT_OF_GAS);
  assert(vm.memory_size == 0);
  assert(vm.gas_remaining == 0);
  evm_destroy(&vm);

  status = evm_init(&vm, nullptr, 0, 3);
  assert(status == EVM_OK);
  status = evm_memory_ensure(&vm, 1);
  assert(status == EVM_OK);
  assert(vm.memory_size == 32);
  assert(vm.gas_remaining == 0);
  evm_destroy(&vm);
}
