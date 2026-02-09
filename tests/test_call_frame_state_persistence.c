#include "test_helpers.h"

void test_call_frame_state_persistence() {
  EVM_State vm;
  uint8_t *code = nullptr;

  EVM_Status status = execute_hex(
      "3615600b576001600055005b60016000535f5f60015f5f30617530f1505f5400",
      120'000, &vm, &code);
  assert(status == EVM_OK);
  assert_top_u64(&vm, 1);
  cleanup(&vm, code);

  static constexpr uint8_t counter_code[17] = {
      0x60, 0x00, 0x54, 0x60, 0x01, 0x01, 0x60, 0x00, 0x55,
      0x60, 0x00, 0x54, 0x60, 0x00, 0x52, 0x60, 0x20,
  };
  static constexpr uint8_t counter_code_tail[3] = {0x60, 0x00, 0xf3};
  uint8_t counter_runtime[20];
  memcpy(counter_runtime, counter_code, sizeof(counter_code));
  memcpy(counter_runtime + sizeof(counter_code), counter_code_tail,
         sizeof(counter_code_tail));

  EVM_ExternalAccount counter_account = {
      .address = uint256_from_u64(0x11),
      .balance = uint256_zero(),
      .code = counter_runtime,
      .code_size = sizeof(counter_runtime),
      .code_hash = uint256_zero(),
  };

  init_vm_from_hex(
      "60205f5f5f5f6011617530f150602060205f5f5f6011617530f15060205100", 120'000,
      &vm, &code);
  vm.external_accounts = &counter_account;
  vm.external_accounts_count = 1;
  status = evm_execute(&vm);
  assert(status == EVM_OK);
  assert_top_u64(&vm, 2);
  cleanup(&vm, code);

  static constexpr uint8_t delegate_runtime[16] = {
      0x60, 0x01, 0x60, 0x00, 0x55, 0x60, 0x00, 0x54,
      0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xf3};

  EVM_ExternalAccount delegate_account = {
      .address = uint256_from_u64(0x11),
      .balance = uint256_zero(),
      .code = delegate_runtime,
      .code_size = sizeof(delegate_runtime),
      .code_hash = uint256_zero(),
  };

  init_vm_from_hex("60205f5f5f6011617530f45060005400", 80'000, &vm, &code);
  vm.external_accounts = &delegate_account;
  vm.external_accounts_count = 1;
  status = evm_execute(&vm);
  assert(status == EVM_OK);
  assert_top_u64(&vm, 1);
  cleanup(&vm, code);
}

