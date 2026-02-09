#include "test_helpers.h"

static EVM_Status execute_hex_in_static_context(const char *hex,
                                                uint64_t gas_limit,
                                                EVM_State *vm, uint8_t **code) {
  size_t size = 0;
  EVM_Status status = evm_load_hex(hex, code, &size);
  assert(status == EVM_OK);
  status = evm_init(vm, *code, size, gas_limit);
  assert(status == EVM_OK);
  vm->is_static_context = true;
  return evm_execute(vm);
}

void test_stack_and_static_context_errors() {
  EVM_State vm;
  uint8_t *code = nullptr;

  EVM_Status status = execute_hex("50", 100U, &vm, &code);
  assert(status == EVM_ERR_STACK_UNDERFLOW);
  cleanup(&vm, code);

  status = execute_hex("600101", 100U, &vm, &code);
  assert(status == EVM_ERR_STACK_UNDERFLOW);
  cleanup(&vm, code);

  status = execute_hex("80", 100U, &vm, &code);
  assert(status == EVM_ERR_STACK_UNDERFLOW);
  cleanup(&vm, code);

  status = execute_hex("600190", 100U, &vm, &code);
  assert(status == EVM_ERR_STACK_UNDERFLOW);
  cleanup(&vm, code);

  size_t overflow_code_size = EVM_STACK_MAX_DEPTH + 1U;
  uint8_t *overflow_code = calloc(overflow_code_size, sizeof(uint8_t));
  assert(overflow_code != nullptr);
  memset(overflow_code, 0x5f, overflow_code_size);
  status = evm_init(&vm, overflow_code, overflow_code_size, 3'000U);
  assert(status == EVM_OK);
  status = evm_execute(&vm);
  assert(status == EVM_ERR_STACK_OVERFLOW);
  evm_destroy(&vm);
  free(overflow_code);

  status = execute_hex_in_static_context("6001600055", 30'000U, &vm, &code);
  assert(status == EVM_ERR_WRITE_PROTECTION);
  cleanup(&vm, code);

  status = execute_hex_in_static_context("602a60015d", 30'000U, &vm, &code);
  assert(status == EVM_ERR_INVALID_OPCODE);
  cleanup(&vm, code);

  status = execute_hex_in_static_context("5f5fa0", 30'000U, &vm, &code);
  assert(status == EVM_ERR_WRITE_PROTECTION);
  cleanup(&vm, code);

  status = execute_hex_in_static_context("5f5f5ff0", 80'000U, &vm, &code);
  assert(status == EVM_ERR_WRITE_PROTECTION);
  cleanup(&vm, code);

  status = execute_hex_in_static_context("5fff", 30'000U, &vm, &code);
  assert(status == EVM_ERR_WRITE_PROTECTION);
  cleanup(&vm, code);

  status =
      execute_hex_in_static_context("5f5f5f5f60015f5ff1", 30'000U, &vm, &code);
  assert(status == EVM_ERR_WRITE_PROTECTION);
  cleanup(&vm, code);
}
