#include "test_helpers.h"

void test_arithmetic_and_stack() {
  EVM_State vm;
  uint8_t *code = nullptr;
  EVM_Status status = execute_hex("6002600301", 100, &vm, &code);
  assert(status == EVM_OK);
  assert(vm.pc == 5);
  assert_top_u64(&vm, 5);
  cleanup(&vm, code);

  status = execute_hex("6003600203", 100, &vm, &code);
  assert(status == EVM_OK);
  assert_top_u64(&vm, 1);
  cleanup(&vm, code);

  status = execute_hex("6002600302", 100, &vm, &code);
  assert(status == EVM_OK);
  assert_top_u64(&vm, 6);
  cleanup(&vm, code);

  status = execute_hex("6006600204", 100, &vm, &code);
  assert(status == EVM_OK);
  assert_top_u64(&vm, 3);
  cleanup(&vm, code);

  status = execute_hex("6007600306", 100, &vm, &code);
  assert(status == EVM_OK);
  assert_top_u64(&vm, 1);
  cleanup(&vm, code);
}

