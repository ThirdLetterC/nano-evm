#include "test_helpers.h"

void test_out_of_gas() {
  EVM_State vm;
  uint8_t *code = nullptr;

  EVM_Status status = execute_hex("6002600301", 8, &vm, &code);
  assert(status == EVM_ERR_OUT_OF_GAS);
  assert(vm.gas_remaining == 0U);
  cleanup(&vm, code);

  status = execute_hex("6001600055", 22'105, &vm, &code);
  assert(status == EVM_ERR_OUT_OF_GAS);
  assert(vm.gas_remaining == 0U);
  cleanup(&vm, code);

  status = execute_hex("60016000a0", 391, &vm, &code);
  assert(status == EVM_ERR_OUT_OF_GAS);
  assert(vm.gas_remaining == 0U);
  cleanup(&vm, code);

  status = execute_hex("6000600055", 2'306, &vm, &code);
  assert(status == EVM_ERR_OUT_OF_GAS);
  assert(vm.gas_remaining == 0U);
  cleanup(&vm, code);
}
