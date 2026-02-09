#include "test_helpers.h"

void test_log_ops() {
  EVM_State vm;
  uint8_t *code = nullptr;

  EVM_Status status = execute_hex("60ff60005360aa60016000a1", 779, &vm, &code);
  assert(status == EVM_OK);
  assert(vm.logs_count == 1);
  assert(vm.logs[0].topics_count == 1);
  assert(vm.logs[0].data_size == 1);
  assert(vm.logs[0].data[0] == 0xff);
  uint256_t topic = uint256_from_u64(0xaa);
  assert(uint256_cmp(&vm.logs[0].topics[0], &topic) == 0);
  assert(vm.gas_remaining == 0);
  cleanup(&vm, code);

  status = execute_hex("60016000a0", 392, &vm, &code);
  assert(status == EVM_OK);
  assert(vm.logs_count == 1);
  assert(vm.logs[0].data_size == 1);
  assert(vm.logs[0].data[0] == 0x00);
  assert(vm.memory_size == 32);
  cleanup(&vm, code);
}

