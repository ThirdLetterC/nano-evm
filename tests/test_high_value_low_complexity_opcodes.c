#include "test_helpers.h"

void test_high_value_low_complexity_opcodes() {
  EVM_State vm;
  uint8_t *code = nullptr;

  EVM_Status status = execute_hex("5f", 2, &vm, &code);
  assert(status == EVM_OK);
  assert_top_u64(&vm, 0);
  cleanup(&vm, code);

  status = execute_hex("6001600250", 8, &vm, &code);
  assert(status == EVM_OK);
  assert(stack_depth(&vm.stack) == 1);
  assert_top_u64(&vm, 1);
  cleanup(&vm, code);

  status = execute_hex("6001600260038190", 100, &vm, &code);
  assert(status == EVM_OK);
  assert(stack_depth(&vm.stack) == 4);
  assert_top_u64(&vm, 3);
  cleanup(&vm, code);

  status = execute_hex("58", 2, &vm, &code);
  assert(status == EVM_OK);
  assert_top_u64(&vm, 0);
  cleanup(&vm, code);

  status = execute_hex("600158", 5, &vm, &code);
  assert(status == EVM_OK);
  assert_top_u64(&vm, 2);
  cleanup(&vm, code);

  status = execute_hex("5a00", 10, &vm, &code);
  assert(status == EVM_OK);
  assert_top_u64(&vm, 8);
  cleanup(&vm, code);

  status = execute_hex("600456005b602a00", 15, &vm, &code);
  assert(status == EVM_OK);
  assert_top_u64(&vm, 0x2a);
  cleanup(&vm, code);

  status = execute_hex("60016008576000005b602a00", 20, &vm, &code);
  assert(status == EVM_OK);
  assert_top_u64(&vm, 0x2a);
  cleanup(&vm, code);

  status = execute_hex("60006008576007005b602a00", 19, &vm, &code);
  assert(status == EVM_OK);
  assert_top_u64(&vm, 7);
  cleanup(&vm, code);

  status = execute_hex("600256", 100, &vm, &code);
  assert(status == EVM_ERR_INVALID_OPCODE);
  cleanup(&vm, code);

  status = execute_hex("600456", 100, &vm, &code);
  assert(status == EVM_ERR_INVALID_OPCODE);
  cleanup(&vm, code);
}

