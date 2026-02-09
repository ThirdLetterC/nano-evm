#include "test_helpers.h"

void test_contract_io_opcodes() {
  EVM_State vm;
  uint8_t *code = nullptr;
  static constexpr uint8_t call_data[4] = {0x11, 0x22, 0x33, 0x44};

  EVM_Status status = execute_hex_with_calldata(
      "600035", call_data, sizeof(call_data), 100, &vm, &code);
  assert(status == EVM_OK);
  uint8_t expected_word[32] = {0};
  expected_word[0] = 0x11;
  expected_word[1] = 0x22;
  expected_word[2] = 0x33;
  expected_word[3] = 0x44;
  assert_top_bytes32(&vm, expected_word);
  cleanup(&vm, code);

  status = execute_hex_with_calldata("600235", call_data, sizeof(call_data),
                                     100, &vm, &code);
  assert(status == EVM_OK);
  uint8_t expected_offset_word[32] = {0};
  expected_offset_word[0] = 0x33;
  expected_offset_word[1] = 0x44;
  assert_top_bytes32(&vm, expected_offset_word);
  cleanup(&vm, code);

  status = execute_hex_with_calldata("36", call_data, sizeof(call_data), 100,
                                     &vm, &code);
  assert(status == EVM_OK);
  assert_top_u64(&vm, 4);
  cleanup(&vm, code);

  status = execute_hex_with_calldata("60056002600037", call_data,
                                     sizeof(call_data), 100, &vm, &code);
  assert(status == EVM_OK);
  assert(vm.memory_size == 32);
  assert(vm.memory[0] == 0x33);
  assert(vm.memory[1] == 0x44);
  assert(vm.memory[2] == 0x00);
  assert(vm.memory[3] == 0x00);
  assert(vm.memory[4] == 0x00);
  cleanup(&vm, code);

  status = execute_hex("38", 100, &vm, &code);
  assert(status == EVM_OK);
  assert_top_u64(&vm, 1);
  cleanup(&vm, code);

  status = execute_hex("60026000600039", 100, &vm, &code);
  assert(status == EVM_OK);
  assert(vm.memory_size == 32);
  assert(vm.memory[0] == 0x60);
  assert(vm.memory[1] == 0x02);
  cleanup(&vm, code);

  status = execute_hex("60036006600039", 100, &vm, &code);
  assert(status == EVM_OK);
  assert(vm.memory_size == 32);
  assert(vm.memory[0] == 0x39);
  assert(vm.memory[1] == 0x00);
  assert(vm.memory[2] == 0x00);
  cleanup(&vm, code);

  status = execute_hex("3d", 100, &vm, &code);
  assert(status == EVM_OK);
  assert_top_u64(&vm, 0);
  cleanup(&vm, code);

  status = execute_hex("5f5f5f3e", 100, &vm, &code);
  assert(status == EVM_OK);
  assert(vm.memory_size == 0);
  cleanup(&vm, code);

  status = execute_hex("60015f5f3e", 100, &vm, &code);
  assert(status == EVM_ERR_INVALID_OPCODE);
  cleanup(&vm, code);
}
