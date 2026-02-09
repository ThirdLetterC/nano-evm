#include "test_helpers.h"

void test_new_context_external_and_copy_opcodes() {
  EVM_State vm;
  uint8_t *code = nullptr;

  static constexpr uint8_t ext_code[3] = {0xaa, 0xbb, 0xcc};
  EVM_ExternalAccount ext_account = {
      .address = uint256_from_u64(0x11),
      .balance = uint256_from_u64(0x77),
      .code = ext_code,
      .code_size = sizeof(ext_code),
      .code_hash = uint256_zero(),
  };
  EVM_ExternalAccount empty_account = {
      .address = uint256_from_u64(0x22),
      .balance = uint256_zero(),
      .code = nullptr,
      .code_size = 0,
      .code_hash = uint256_zero(),
  };

  EVM_BlockHashEntry block_hash = {
      .number = uint256_from_u64(999),
      .hash = uint256_from_u64(0xabc),
  };

  init_vm_from_hex("303233343a414243444546474800", 200, &vm, &code);
  vm.address = uint256_from_u64(1);
  vm.origin = uint256_from_u64(2);
  vm.caller = uint256_from_u64(3);
  vm.call_value = uint256_from_u64(4);
  vm.gas_price = uint256_from_u64(5);
  vm.coinbase = uint256_from_u64(6);
  vm.timestamp = uint256_from_u64(7);
  vm.block_number = uint256_from_u64(8);
  vm.prev_randao = uint256_from_u64(9);
  vm.block_gas_limit = uint256_from_u64(10);
  vm.chain_id = uint256_from_u64(11);
  vm.self_balance = uint256_from_u64(12);
  vm.base_fee = uint256_from_u64(13);
  EVM_Status status = evm_execute(&vm);
  assert(status == EVM_OK);
  assert(stack_depth(&vm.stack) == 13);
  for (uint64_t expected = 13; expected >= 1; --expected) {
    uint256_t value = uint256_zero();
    assert(stack_pop(&vm.stack, &value) == STACK_OK);
    uint256_t expected_word = uint256_from_u64(expected);
    assert(uint256_cmp(&value, &expected_word) == 0);
  }
  cleanup(&vm, code);

  init_vm_from_hex("601131", 3'000, &vm, &code);
  vm.external_accounts = &ext_account;
  vm.external_accounts_count = 1;
  status = evm_execute(&vm);
  assert(status == EVM_OK);
  assert_top_u64(&vm, 0x77);
  cleanup(&vm, code);

  init_vm_from_hex("60113b", 3'000, &vm, &code);
  vm.external_accounts = &ext_account;
  vm.external_accounts_count = 1;
  status = evm_execute(&vm);
  assert(status == EVM_OK);
  assert_top_u64(&vm, 3);
  cleanup(&vm, code);

  init_vm_from_hex("60036000600060113c", 3'000, &vm, &code);
  vm.external_accounts = &ext_account;
  vm.external_accounts_count = 1;
  status = evm_execute(&vm);
  assert(status == EVM_OK);
  assert(vm.memory_size == 32);
  assert(vm.memory[0] == 0xaa);
  assert(vm.memory[1] == 0xbb);
  assert(vm.memory[2] == 0xcc);
  cleanup(&vm, code);

  init_vm_from_hex("60113f", 3'000, &vm, &code);
  vm.external_accounts = &ext_account;
  vm.external_accounts_count = 1;
  status = evm_execute(&vm);
  assert(status == EVM_OK);
  const union ethash_hash256 code_hash =
      ethash_keccak256(ext_code, sizeof(ext_code));
  assert_top_bytes32(&vm, code_hash.bytes);
  cleanup(&vm, code);

  init_vm_from_hex("60223f", 3'000, &vm, &code);
  vm.external_accounts = &empty_account;
  vm.external_accounts_count = 1;
  status = evm_execute(&vm);
  assert(status == EVM_OK);
  assert_top_u64(&vm, 0);
  cleanup(&vm, code);

  init_vm_from_hex("303f00", 500, &vm, &code);
  vm.address = uint256_from_u64(1);
  status = evm_execute(&vm);
  assert(status == EVM_OK);
  const union ethash_hash256 self_hash = ethash_keccak256(code, 3U);
  assert_top_bytes32(&vm, self_hash.bytes);
  cleanup(&vm, code);

  init_vm_from_hex("6103e740", 500, &vm, &code);
  vm.block_number = uint256_from_u64(1'000);
  vm.block_hashes = &block_hash;
  vm.block_hashes_count = 1;
  status = evm_execute(&vm);
  assert(status == EVM_OK);
  assert_top_u64(&vm, 0xabc);
  cleanup(&vm, code);

  init_vm_from_hex("6102bc40", 500, &vm, &code);
  vm.block_number = uint256_from_u64(1'000);
  vm.block_hashes = &block_hash;
  vm.block_hashes_count = 1;
  status = evm_execute(&vm);
  assert(status == EVM_OK);
  assert_top_u64(&vm, 0);
  cleanup(&vm, code);

  status = execute_hex("5f49", 500, &vm, &code);
  assert(status == EVM_ERR_INVALID_OPCODE);
  cleanup(&vm, code);

  status = execute_hex("600249", 500, &vm, &code);
  assert(status == EVM_ERR_INVALID_OPCODE);
  cleanup(&vm, code);

  status = execute_hex("60aa60005360bb6001536002600060025e", 200, &vm, &code);
  assert(status == EVM_ERR_INVALID_OPCODE);
  cleanup(&vm, code);
}
