#include "test_helpers.h"

void test_core_arithmetic_logic_opcodes() {
  EVM_State vm;
  uint8_t *code = nullptr;

  EVM_Status status = execute_hex("6002600310", 100, &vm, &code);
  assert(status == EVM_OK);
  assert_top_u64(&vm, 1);
  cleanup(&vm, code);

  status = execute_hex("6003600211", 100, &vm, &code);
  assert(status == EVM_OK);
  assert_top_u64(&vm, 1);
  cleanup(&vm, code);

  status = execute_hex("7ffffffffffffffffffffffffffffffffffffffffffffffffffffff"
                       "fffffffffff600112",
                       100, &vm, &code);
  assert(status == EVM_OK);
  assert_top_u64(&vm, 1);
  cleanup(&vm, code);

  status = execute_hex("60017ffffffffffffffffffffffffffffffffffffffffffffffffff"
                       "fffffffffffffff13",
                       100, &vm, &code);
  assert(status == EVM_OK);
  assert_top_u64(&vm, 1);
  cleanup(&vm, code);

  status = execute_hex("6007600714", 100, &vm, &code);
  assert(status == EVM_OK);
  assert_top_u64(&vm, 1);
  cleanup(&vm, code);

  status = execute_hex("600015", 100, &vm, &code);
  assert(status == EVM_OK);
  assert_top_u64(&vm, 1);
  cleanup(&vm, code);

  status = execute_hex("600f603316", 100, &vm, &code);
  assert(status == EVM_OK);
  assert_top_u64(&vm, 0x03);
  cleanup(&vm, code);

  status = execute_hex("600f603017", 100, &vm, &code);
  assert(status == EVM_OK);
  assert_top_u64(&vm, 0x3f);
  cleanup(&vm, code);

  status = execute_hex("60ff600f18", 100, &vm, &code);
  assert(status == EVM_OK);
  assert_top_u64(&vm, 0xf0);
  cleanup(&vm, code);

  status = execute_hex("600f19", 100, &vm, &code);
  assert(status == EVM_OK);
  uint8_t not_expected[32];
  memset(not_expected, 0xff, sizeof(not_expected));
  not_expected[31] = 0xf0;
  assert_top_bytes32(&vm, not_expected);
  cleanup(&vm, code);

  status = execute_hex("601e6112341a", 100, &vm, &code);
  assert(status == EVM_OK);
  assert_top_u64(&vm, 0x12);
  cleanup(&vm, code);

  status = execute_hex("600860011b", 100, &vm, &code);
  assert(status == EVM_OK);
  assert_top_u64(&vm, 0x100);
  cleanup(&vm, code);

  status = execute_hex("60086101001c", 100, &vm, &code);
  assert(status == EVM_OK);
  assert_top_u64(&vm, 1);
  cleanup(&vm, code);

  status = execute_hex("60015f6002031d", 100, &vm, &code);
  assert(status == EVM_OK);
  uint8_t sar_expected[32];
  memset(sar_expected, 0xff, sizeof(sar_expected));
  assert_top_bytes32(&vm, sar_expected);
  cleanup(&vm, code);

  status = execute_hex("60026003600508", 100, &vm, &code);
  assert(status == EVM_OK);
  assert_top_u64(&vm, 0);
  cleanup(&vm, code);

  status = execute_hex(
      "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff6001"
      "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff08",
      200, &vm, &code);
  assert(status == EVM_OK);
  assert_top_u64(&vm, 1);
  cleanup(&vm, code);

  status = execute_hex("60036004600509", 100, &vm, &code);
  assert(status == EVM_OK);
  assert_top_u64(&vm, 2);
  cleanup(&vm, code);

  status = execute_hex("600260080a", 200, &vm, &code);
  assert(status == EVM_OK);
  assert_top_u64(&vm, 0x100);
  cleanup(&vm, code);

  status = execute_hex("600060800b", 100, &vm, &code);
  assert(status == EVM_OK);
  uint8_t signextend_expected[32];
  memset(signextend_expected, 0xff, sizeof(signextend_expected));
  signextend_expected[31] = 0x80;
  assert_top_bytes32(&vm, signextend_expected);
  cleanup(&vm, code);
}

