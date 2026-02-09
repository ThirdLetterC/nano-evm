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
}
