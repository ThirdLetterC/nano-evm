#include "test_helpers.h"

void test_new_signed_and_transient_opcodes() {
  EVM_State vm;
  uint8_t *code = nullptr;

  EVM_Status status = execute_hex("5f600403600205", 100, &vm, &code);
  assert(status == EVM_OK);
  uint8_t minus_two[32];
  memset(minus_two, 0xff, sizeof(minus_two));
  minus_two[31] = 0xfe;
  assert_top_bytes32(&vm, minus_two);
  cleanup(&vm, code);

  status = execute_hex("5f600503600307", 100, &vm, &code);
  assert(status == EVM_OK);
  assert_top_bytes32(&vm, minus_two);
  cleanup(&vm, code);

  status = execute_hex("6005600005", 100, &vm, &code);
  assert(status == EVM_OK);
  assert_top_u64(&vm, 0);
  cleanup(&vm, code);

  status = execute_hex("6005600007", 100, &vm, &code);
  assert(status == EVM_OK);
  assert_top_u64(&vm, 0);
  cleanup(&vm, code);

  status = execute_hex("602a60015d60015c", 300, &vm, &code);
  assert(status == EVM_ERR_INVALID_OPCODE);
  cleanup(&vm, code);
}
