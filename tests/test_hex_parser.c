#include "test_helpers.h"

void test_hex_parser() {
  uint8_t *code = nullptr;
  size_t size = 0;
  EVM_Status status = evm_load_hex("0x600A", &code, &size);
  assert(status == EVM_OK);
  assert(size == 2);
  assert(code[0] == 0x60 && code[1] == 0x0a);
  free(code);

  status = evm_load_hex("600", &code, &size);
  assert(status == EVM_ERR_HEX_PARSE);
  assert(code == nullptr);
  assert(size == 0);

  status = evm_load_hex("0x60 0a", &code, &size);
  assert(status == EVM_ERR_HEX_PARSE);
  assert(code == nullptr);
  assert(size == 0U);

  status = evm_load_hex("0x600a \t\n", &code, &size);
  assert(status == EVM_OK);
  assert(code != nullptr);
  assert(size == 2U);
  assert(code[0] == 0x60U && code[1] == 0x0aU);
  free(code);
}
