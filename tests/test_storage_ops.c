#include "test_helpers.h"

void test_storage_ops() {
  EVM_State vm;
  uint8_t *code = nullptr;

  EVM_Status status = execute_hex("6001600055600054", 22209, &vm, &code);
  assert(status == EVM_OK);
  assert_top_u64(&vm, 1);
  assert(vm.gas_remaining == 0);
  assert(vm.storage_count == 1);
  cleanup(&vm, code);

  status = execute_hex("60016000556000600055600054", 24'515, &vm, &code);
  assert(status == EVM_OK);
  assert_top_u64(&vm, 0);
  assert(vm.gas_remaining == 6'663);
  cleanup(&vm, code);

  status = execute_hex("60016000556001600055", 24'515, &vm, &code);
  assert(status == EVM_OK);
  assert(vm.gas_remaining == 2'303);
  cleanup(&vm, code);
}
