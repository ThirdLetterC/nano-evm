#include "test_helpers.h"

void test_new_call_create_and_selfdestruct_opcodes() {
  EVM_State vm;
  uint8_t *code = nullptr;

  static constexpr uint8_t calldata_echo4_code[9] = {
      0x60, 0x04, 0x5f, 0x5f, 0x37, 0x60, 0x04, 0x5f, 0xf3};
  EVM_ExternalAccount ext_account = {
      .address = uint256_from_u64(0x11),
      .balance = uint256_zero(),
      .code = calldata_echo4_code,
      .code_size = sizeof(calldata_echo4_code),
      .code_hash = uint256_zero(),
  };
  static constexpr uint8_t storage_write_code[5] = {0x60, 0x01, 0x60, 0x00,
                                                    0x55};
  EVM_ExternalAccount static_mutator = {
      .address = uint256_from_u64(0x11),
      .balance = uint256_zero(),
      .code = storage_write_code,
      .code_size = sizeof(storage_write_code),
      .code_hash = uint256_zero(),
  };
  static constexpr uint8_t caller_balance_probe_code[8] = {
      0x33, 0x31, 0x5f, 0x52, 0x60, 0x20, 0x5f, 0xf3};
  EVM_ExternalAccount caller_balance_probe = {
      .address = uint256_from_u64(0x11),
      .balance = uint256_zero(),
      .code = caller_balance_probe_code,
      .code_size = sizeof(caller_balance_probe_code),
      .code_hash = uint256_zero(),
  };
  static constexpr uint8_t warm_probe_code[4] = {0x60, 0x00, 0x54, 0x00};
  EVM_ExternalAccount warm_probe = {
      .address = uint256_from_u64(0x11),
      .balance = uint256_zero(),
      .code = warm_probe_code,
      .code_size = sizeof(warm_probe_code),
      .code_hash = uint256_zero(),
  };
  static constexpr uint8_t selfdestruct_code[3] = {0x60, 0x22, 0xff};
  EVM_ExternalAccount selfdestruct_account = {
      .address = uint256_from_u64(0x11),
      .balance = uint256_zero(),
      .code = selfdestruct_code,
      .code_size = sizeof(selfdestruct_code),
      .code_hash = uint256_zero(),
  };
  EVM_ExternalAccount high_bits_balance_account = {
      .address = uint256_from_u64(0x11),
      .balance = uint256_from_u64(42),
      .code = nullptr,
      .code_size = 0,
      .code_hash = uint256_zero(),
  };

  EVM_Status status = execute_hex("5f5f5360015f5ff0", 40'000, &vm, &code);
  assert(status == EVM_OK);
  uint256_t create_address = uint256_zero();
  assert(stack_peek(&vm.stack, &create_address) == STACK_OK);
  assert(!uint256_is_zero(&create_address));
  cleanup(&vm, code);

  status = execute_hex("5f5f53602a60015f5ff5", 40'000, &vm, &code);
  assert(status == EVM_OK);
  uint256_t create2_address = uint256_zero();
  assert(stack_peek(&vm.stack, &create2_address) == STACK_OK);
  assert(!uint256_is_zero(&create2_address));
  assert(uint256_cmp(&create_address, &create2_address) != 0);
  cleanup(&vm, code);

  // CREATE success must clear returndata, even when init code returns bytes.
  status = execute_hex("600a600e5f39600a5f5ff0503d0060aa60005360016000f3",
                       40'000, &vm, &code);
  assert(status == EVM_OK);
  assert_top_u64(&vm, 0);
  cleanup(&vm, code);

  // CREATE failure from REVERT must preserve revert bytes in returndata.
  status = execute_hex("600a600e5f39600a5f5ff0503d0060aa60005360016000fd",
                       40'000, &vm, &code);
  assert(status == EVM_OK);
  assert_top_u64(&vm, 1);
  cleanup(&vm, code);

  // CREATE code-deposit failure must keep initcode returndata.
  status = execute_hex("600a600c5f39600a5f5ff00060aa60005360016000f3", 32'200,
                       &vm, &code);
  assert(status == EVM_OK);
  assert_top_u64(&vm, 0);
  assert(vm.return_data_size == 1U);
  assert(vm.return_data != nullptr);
  assert(vm.return_data[0] == 0xaaU);
  cleanup(&vm, code);

  // EIP-3541: runtime code beginning with 0xef is rejected.
  status = execute_hex("600a600c5f39600a5f5ff00060ef60005360016000f3", 50'000,
                       &vm, &code);
  assert(status == EVM_OK);
  assert_top_u64(&vm, 0);
  assert(vm.return_data_size == 1U);
  assert(vm.return_data != nullptr);
  assert(vm.return_data[0] == 0xefU);
  cleanup(&vm, code);

  init_vm_from_hex("5f5f5ff0", 40'000, &vm, &code);
  vm.address = uint256_from_u64(0x77);
  uint256_t collision_address = derive_create_address_expected(0x77, 0U);
  EVM_ExternalAccount nonce_collision = {
      .address = collision_address,
      .balance = uint256_zero(),
      .code = nullptr,
      .code_size = 0,
      .code_hash = uint256_zero(),
      .nonce = 1U,
  };
  vm.external_accounts = &nonce_collision;
  vm.external_accounts_count = 1;
  status = evm_execute(&vm);
  assert(status == EVM_OK);
  assert_top_u64(&vm, 0);
  assert(vm.gas_remaining == 124U);
  bool collision_target_is_warm = false;
  for (size_t i = 0; i < vm.warm_accounts_count; ++i) {
    if (uint256_cmp(&vm.warm_accounts[i], &collision_address) == 0) {
      collision_target_is_warm = true;
      break;
    }
  }
  assert(collision_target_is_warm);
  cleanup(&vm, code);

  init_vm_from_hex("5f5f5ff0", 40'000, &vm, &code);
  vm.address = uint256_from_u64(0x77);
  EVM_ExternalAccount balance_only_account = {
      .address = collision_address,
      .balance = uint256_from_u64(5),
      .code = nullptr,
      .code_size = 0,
      .code_hash = uint256_zero(),
      .nonce = 0U,
  };
  vm.external_accounts = &balance_only_account;
  vm.external_accounts_count = 1;
  status = evm_execute(&vm);
  assert(status == EVM_OK);
  uint256_t create_result = uint256_zero();
  assert(stack_peek(&vm.stack, &create_result) == STACK_OK);
  assert(uint256_cmp(&create_result, &collision_address) == 0);
  cleanup(&vm, code);

  init_vm_from_hex("61c0015f5ff000", 200'000, &vm, &code);
  status = evm_execute(&vm);
  assert(status == EVM_OK);
  assert_top_u64(&vm, 0);
  bool caller_nonce_incremented = false;
  for (size_t i = 0; i < vm.runtime_accounts_count; ++i) {
    if (uint256_cmp(&vm.runtime_accounts[i].address, &vm.address) == 0 &&
        vm.runtime_accounts[i].nonce == 1U) {
      caller_nonce_incremented = true;
    }
  }
  assert(!caller_nonce_incremented);
  cleanup(&vm, code);

  status = execute_hex("6060600053600060015360606002536000600353605360045360606"
                       "0055360016006536060600753"
                       "600060085360f3600953600a5f5ff0803b00",
                       120'000, &vm, &code);
  assert(status == EVM_OK);
  assert_top_u64(&vm, 1);
  uint256_t ignored = uint256_zero();
  assert(stack_pop(&vm.stack, &ignored) == STACK_OK);
  uint256_t deployed_address = uint256_zero();
  assert(stack_peek(&vm.stack, &deployed_address) == STACK_OK);
  assert(!uint256_is_zero(&deployed_address));
  cleanup(&vm, code);

  init_vm_from_hex("5f5f5f5f5f5f5ff1", 2'000, &vm, &code);
  vm.address = uint256_from_u64(1);
  status = evm_execute(&vm);
  assert(status == EVM_OK);
  assert_top_u64(&vm, 1);
  cleanup(&vm, code);

  init_vm_from_hex("5f5f5f5f5f5f5ff2", 2'000, &vm, &code);
  vm.address = uint256_from_u64(1);
  status = evm_execute(&vm);
  assert(status == EVM_OK);
  assert_top_u64(&vm, 1);
  cleanup(&vm, code);

  init_vm_from_hex("5f5f5f5f5f5ff4", 2'000, &vm, &code);
  vm.address = uint256_from_u64(1);
  status = evm_execute(&vm);
  assert(status == EVM_OK);
  assert_top_u64(&vm, 1);
  cleanup(&vm, code);

  init_vm_from_hex("5f5f5f5f5f5ffa", 2'000, &vm, &code);
  vm.address = uint256_from_u64(1);
  status = evm_execute(&vm);
  assert(status == EVM_OK);
  assert_top_u64(&vm, 1);
  cleanup(&vm, code);

  init_vm_from_hex("5f5f5f5f5f6011612710f15f5f5f5f5f6011612710f100", 10'000,
                   &vm, &code);
  vm.external_accounts = &warm_probe;
  vm.external_accounts_count = 1;
  status = evm_execute(&vm);
  assert(status == EVM_OK);
  assert(vm.gas_remaining == 5'062);
  cleanup(&vm, code);

  status = execute_hex("602a60015d60015c", 300, &vm, &code);
  assert(status == EVM_ERR_INVALID_OPCODE);
  cleanup(&vm, code);

  status = execute_hex("5fff", 6'000, &vm, &code);
  assert(status == EVM_OK);
  assert(stack_depth(&vm.stack) == 0);
  cleanup(&vm, code);

  init_vm_from_hex("5f5f5f5f600360115ff1601131", 60'000, &vm, &code);
  vm.self_balance = uint256_from_u64(10);
  status = evm_execute(&vm);
  assert(status == EVM_OK);
  assert_top_u64(&vm, 3);
  assert(stack_pop(&vm.stack, &ignored) == STACK_OK);
  uint256_t success_flag = uint256_zero();
  uint256_t expected_one = uint256_from_u64(1);
  uint256_t expected_seven = uint256_from_u64(7);
  uint256_t expected_target = uint256_from_u64(0x11);
  uint256_t expected_three = uint256_from_u64(3);
  assert(stack_peek(&vm.stack, &success_flag) == STACK_OK);
  assert(uint256_cmp(&success_flag, &expected_one) == 0);
  assert(uint256_cmp(&vm.self_balance, &expected_seven) == 0);
  bool found_target_balance = false;
  for (size_t i = 0; i < vm.runtime_accounts_count; ++i) {
    if (uint256_cmp(&vm.runtime_accounts[i].address, &expected_target) == 0) {
      assert(uint256_cmp(&vm.runtime_accounts[i].balance, &expected_three) ==
             0);
      assert(!vm.runtime_accounts[i].destroyed);
      found_target_balance = true;
    }
  }
  assert(found_target_balance);
  cleanup(&vm, code);

  init_vm_from_hex(
      "7f80000000000000000000000000000000000000000000000000000000000000113100",
      30'000, &vm, &code);
  vm.external_accounts = &high_bits_balance_account;
  vm.external_accounts_count = 1;
  status = evm_execute(&vm);
  assert(status == EVM_OK);
  assert_top_u64(&vm, 42);
  cleanup(&vm, code);

  init_vm_from_hex("6020600060005f60036011612710f160005100", 40'000, &vm,
                   &code);
  vm.address = uint256_from_u64(1);
  vm.self_balance = uint256_from_u64(10);
  vm.external_accounts = &caller_balance_probe;
  vm.external_accounts_count = 1;
  status = evm_execute(&vm);
  assert(status == EVM_OK);
  assert_top_u64(&vm, 7);
  assert(stack_pop(&vm.stack, &ignored) == STACK_OK);
  assert_top_u64(&vm, 1);
  assert(uint256_cmp(&vm.self_balance, &expected_seven) == 0);
  cleanup(&vm, code);

  init_vm_from_hex("5f5f5f5f601160fffa", 5'000, &vm, &code);
  vm.external_accounts = &static_mutator;
  vm.external_accounts_count = 1;
  status = evm_execute(&vm);
  assert(status == EVM_OK);
  assert_top_u64(&vm, 0);
  cleanup(&vm, code);

  init_vm_from_hex("6000600060006000600060116064f15060113b00", 80'000, &vm,
                   &code);
  vm.external_accounts = &selfdestruct_account;
  vm.external_accounts_count = 1;
  status = evm_execute(&vm);
  assert(status == EVM_OK);
  assert_top_u64(&vm, 3);
  cleanup(&vm, code);

  init_vm_from_hex("6022ff", 40'000, &vm, &code);
  vm.address = uint256_from_u64(0x99);
  vm.self_balance = uint256_from_u64(9);
  status = evm_execute(&vm);
  assert(status == EVM_OK);
  assert(uint256_is_zero(&vm.self_balance));
  bool found_beneficiary = false;
  bool found_self = false;
  uint256_t expected_beneficiary = uint256_from_u64(0x22);
  uint256_t expected_nine = uint256_from_u64(9);
  for (size_t i = 0; i < vm.runtime_accounts_count; ++i) {
    if (uint256_cmp(&vm.runtime_accounts[i].address, &expected_beneficiary) ==
        0) {
      assert(uint256_cmp(&vm.runtime_accounts[i].balance, &expected_nine) == 0);
      assert(!vm.runtime_accounts[i].destroyed);
      found_beneficiary = true;
    }
    if (uint256_cmp(&vm.runtime_accounts[i].address, &vm.address) == 0) {
      assert(uint256_is_zero(&vm.runtime_accounts[i].balance));
      assert(vm.runtime_accounts[i].destroyed);
      found_self = true;
    }
  }
  assert(found_beneficiary);
  assert(found_self);
  cleanup(&vm, code);

  init_vm_from_hex("6099ff", 10'000, &vm, &code);
  vm.address = uint256_from_u64(0x99);
  vm.self_balance = uint256_from_u64(9);
  status = evm_execute(&vm);
  assert(status == EVM_OK);
  assert(uint256_is_zero(&vm.self_balance));
  found_self = false;
  for (size_t i = 0; i < vm.runtime_accounts_count; ++i) {
    if (uint256_cmp(&vm.runtime_accounts[i].address, &vm.address) == 0) {
      assert(uint256_is_zero(&vm.runtime_accounts[i].balance));
      assert(vm.runtime_accounts[i].destroyed);
      found_self = true;
    }
  }
  assert(found_self);
  cleanup(&vm, code);

  init_vm_from_hex("6022ff", 40'000, &vm, &code);
  vm.address = uint256_from_u64(0x99);
  vm.self_balance = uint256_from_u64(9);
  vm.runtime_accounts = calloc(1U, sizeof(EVM_RuntimeAccount));
  assert(vm.runtime_accounts != nullptr);
  vm.runtime_accounts_count = 1U;
  vm.runtime_accounts_capacity = 1U;
  vm.runtime_accounts[0].address = vm.address;
  vm.runtime_accounts[0].balance = vm.self_balance;
  vm.runtime_accounts[0].code = vm.code;
  vm.runtime_accounts[0].code_size = vm.code_size;
  vm.runtime_accounts[0].created_in_transaction = true;
  status = evm_execute(&vm);
  assert(status == EVM_OK);
  assert(uint256_is_zero(&vm.self_balance));
  found_beneficiary = false;
  found_self = false;
  for (size_t i = 0; i < vm.runtime_accounts_count; ++i) {
    if (uint256_cmp(&vm.runtime_accounts[i].address, &expected_beneficiary) ==
        0) {
      assert(uint256_cmp(&vm.runtime_accounts[i].balance, &expected_nine) == 0);
      assert(!vm.runtime_accounts[i].destroyed);
      found_beneficiary = true;
    }
    if (uint256_cmp(&vm.runtime_accounts[i].address, &vm.address) == 0) {
      assert(uint256_is_zero(&vm.runtime_accounts[i].balance));
      assert(vm.runtime_accounts[i].destroyed);
      found_self = true;
    }
  }
  assert(found_beneficiary);
  assert(found_self);
  cleanup(&vm, code);

  init_vm_from_hex(
      "60aa5f5360bb60015360cc60025360dd6003536004600460045f5f60116064f1", 4'000,
      &vm, &code);
  vm.external_accounts = &ext_account;
  vm.external_accounts_count = 1;
  status = evm_execute(&vm);
  assert(status == EVM_OK);
  assert_top_u64(&vm, 1);
  assert(vm.return_data_size == 4);
  assert(vm.return_data != nullptr);
  assert(vm.return_data[0] == 0xaa);
  assert(vm.return_data[1] == 0xbb);
  assert(vm.return_data[2] == 0xcc);
  assert(vm.return_data[3] == 0xdd);
  assert(vm.memory_size == 32);
  assert(vm.memory[4] == 0xaa);
  assert(vm.memory[5] == 0xbb);
  assert(vm.memory[6] == 0xcc);
  assert(vm.memory[7] == 0xdd);
  cleanup(&vm, code);

  init_vm_from_hex("600460005f5f600260116064f1", 50'000, &vm, &code);
  vm.external_accounts = &ext_account;
  vm.external_accounts_count = 1;
  vm.self_balance = uint256_from_u64(1);
  status = evm_execute(&vm);
  assert(status == EVM_OK);
  assert_top_u64(&vm, 0);
  assert(vm.return_data_size == 0);
  assert(vm.memory_size == 32);
  assert(vm.memory[0] == 0);
  assert(vm.memory[1] == 0);
  assert(vm.memory[2] == 0);
  assert(vm.memory[3] == 0);
  cleanup(&vm, code);
}
