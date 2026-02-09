#include "test_helpers.h"

void test_sub_underflow_wraps() {
  EVM_State vm;
  uint8_t *code = nullptr;
  EVM_Status status = execute_hex("6001600203", 100, &vm, &code);
  assert(status == EVM_OK);

  uint256_t top = uint256_zero();
  uint8_t bytes[32];
  assert(stack_peek(&vm.stack, &top) == STACK_OK);
  uint256_to_be_bytes(&top, bytes);
  for (size_t i = 0; i < sizeof(bytes); ++i) {
    assert(bytes[i] == 0xff);
  }

  cleanup(&vm, code);
}

