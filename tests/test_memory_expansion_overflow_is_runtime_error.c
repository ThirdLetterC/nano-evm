#include "test_helpers.h"

void test_memory_expansion_overflow_is_runtime_error() {
  EVM_State vm;
  uint8_t *code = nullptr;

  EVM_Status status =
      execute_hex("60aa67fffffffffffffffe5300", 100'000, &vm, &code);
  assert(status == EVM_ERR_RUNTIME);
  cleanup(&vm, code);
}
