#include "test_helpers.h"

void test_div_by_zero_returns_zero() {
  EVM_State vm;
  uint8_t *code = nullptr;
  EVM_Status status = execute_hex("6005600004", 100, &vm, &code);
  assert(status == EVM_OK);
  assert_top_u64(&vm, 0);
  cleanup(&vm, code);
}
