#include "test_helpers.h"

void test_invalid_opcode_and_bytecode() {
  EVM_State vm;
  uint8_t *code = nullptr;

  EVM_Status status = execute_hex("fe", 100, &vm, &code);
  assert(status == EVM_ERR_INVALID_OPCODE);
  assert(vm.gas_remaining == 0);
  cleanup(&vm, code);

  status = execute_hex("61ff", 100, &vm, &code);
  assert(status == EVM_ERR_INVALID_BYTECODE);
  cleanup(&vm, code);
}

