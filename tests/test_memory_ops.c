#include "test_helpers.h"

void test_memory_ops() {
  EVM_State vm;
  uint8_t *code = nullptr;

  EVM_Status status = execute_hex("602a600052600051", 18, &vm, &code);
  assert(status == EVM_OK);
  assert_top_u64(&vm, 0x2a);
  assert(vm.memory_size == 32);
  assert(vm.memory[31] == 0x2a);
  assert(vm.gas_remaining == 0);
  cleanup(&vm, code);

  status = execute_hex("60ff600053", 12, &vm, &code);
  assert(status == EVM_OK);
  assert(vm.memory_size == 32);
  assert(vm.memory[0] == 0xff);
  cleanup(&vm, code);

  status = execute_hex("600060005259", 14, &vm, &code);
  assert(status == EVM_OK);
  assert_top_u64(&vm, 32);
  cleanup(&vm, code);
}

