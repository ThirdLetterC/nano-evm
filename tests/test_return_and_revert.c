#include "test_helpers.h"

void test_return_and_revert() {
  EVM_State vm;
  uint8_t *code = nullptr;

  EVM_Status status = execute_hex("60aa60005360016000f3fe", 18, &vm, &code);
  assert(status == EVM_OK);
  assert(vm.pc == 10);
  assert(vm.return_data_size == 1);
  assert(vm.return_data != nullptr);
  assert(vm.return_data[0] == 0xaa);
  cleanup(&vm, code);

  status = execute_hex("60ab60005360ff60005560016000a060016000fd", 22'513, &vm,
                       &code);
  assert(status == EVM_ERR_REVERT);
  assert(vm.return_data_size == 1);
  assert(vm.return_data != nullptr);
  assert(vm.return_data[0] == 0xab);
  assert(vm.storage_count == 0);
  assert(vm.logs_count == 0);
  assert(vm.gas_remaining == 0);
  cleanup(&vm, code);
}
