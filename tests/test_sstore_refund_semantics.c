#include "test_helpers.h"

void test_sstore_refund_semantics() {
  EVM_State vm;
  uint8_t *code = nullptr;

  EVM_Status status = execute_hex("60016000556000600055", 24'515, &vm, &code);
  assert(status == EVM_OK);
  assert(vm.gas_remaining == 6'745);
  assert(vm.storage_count == 1);
  cleanup(&vm, code);

  size_t code_size = 0;
  status = evm_load_hex("6000600055", &code, &code_size);
  assert(status == EVM_OK);

  status = evm_init(&vm, code, code_size, 7'106);
  assert(status == EVM_OK);

  vm.storage = calloc(1, sizeof(EVM_StorageEntry));
  assert(vm.storage != nullptr);
  vm.storage_count = 1;
  vm.storage_capacity = 1;
  vm.storage[0].key = uint256_zero();
  vm.storage[0].value = uint256_from_u64(1);

  status = evm_execute(&vm);
  assert(status == EVM_OK);
  assert(vm.gas_remaining == 3'101);
  assert(vm.storage_count == 1);
  uint256_t zero = uint256_zero();
  assert(uint256_cmp(&vm.storage[0].value, &zero) == 0);
  cleanup(&vm, code);
}
