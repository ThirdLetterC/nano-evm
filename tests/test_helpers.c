#include "test_helpers.h"

EVM_Status execute_hex(const char *hex, uint64_t gas_limit, EVM_State *vm,
                       uint8_t **code) {
  size_t size = 0;
  EVM_Status status = evm_load_hex(hex, code, &size);
  assert(status == EVM_OK);
  status = evm_init(vm, *code, size, gas_limit);
  assert(status == EVM_OK);
  return evm_execute(vm);
}

EVM_Status execute_hex_with_calldata(const char *hex, const uint8_t *call_data,
                                     size_t call_data_size, uint64_t gas_limit,
                                     EVM_State *vm, uint8_t **code) {
  size_t size = 0;
  EVM_Status status = evm_load_hex(hex, code, &size);
  assert(status == EVM_OK);
  status = evm_init(vm, *code, size, gas_limit);
  assert(status == EVM_OK);
  vm->call_data = call_data;
  vm->call_data_size = call_data_size;
  return evm_execute(vm);
}

void init_vm_from_hex(const char *hex, uint64_t gas_limit, EVM_State *vm,
                      uint8_t **code) {
  size_t size = 0;
  EVM_Status status = evm_load_hex(hex, code, &size);
  assert(status == EVM_OK);
  status = evm_init(vm, *code, size, gas_limit);
  assert(status == EVM_OK);
}

void cleanup(EVM_State *vm, uint8_t *code) {
  evm_destroy(vm);
  free(code);
}

EVM_Status execute_toy_source(const char *source, uint64_t gas_limit,
                              EVM_State *vm, uint8_t **code) {
  char error[256] = {0};
  size_t code_size = 0;
  NanoSol_Status compile_status =
      nanosol_compile(source, code, &code_size, error, sizeof(error));
  assert(compile_status == NANOSOL_OK);
  EVM_Status status = evm_init(vm, *code, code_size, gas_limit);
  assert(status == EVM_OK);
  return evm_execute(vm);
}

void assert_top_u64(const EVM_State *vm, uint64_t expected) {
  uint256_t top = uint256_zero();
  assert(stack_peek(&vm->stack, &top) == STACK_OK);
  uint256_t expected_word = uint256_from_u64(expected);
  assert(uint256_cmp(&top, &expected_word) == 0);
}

void assert_top_bytes32(const EVM_State *vm, const uint8_t expected[32]) {
  uint256_t top = uint256_zero();
  uint8_t bytes[32];
  assert(stack_peek(&vm->stack, &top) == STACK_OK);
  uint256_to_be_bytes(&top, bytes);
  assert(memcmp(bytes, expected, 32) == 0);
}

void assert_return_u64(const EVM_State *vm, uint64_t expected) {
  assert(vm->return_data != nullptr);
  assert(vm->return_data_size == 32);
  uint256_t actual = uint256_zero();
  uint256_from_be_bytes(&actual, vm->return_data);
  uint256_t expected_word = uint256_from_u64(expected);
  assert(uint256_cmp(&actual, &expected_word) == 0);
}

static size_t encode_rlp_nonce(const uint256_t *nonce, uint8_t out[33]) {
  if (nonce == nullptr || uint256_is_zero(nonce)) {
    out[0] = 0x80U;
    return 1U;
  }

  uint8_t be[32];
  uint256_to_be_bytes(nonce, be);

  size_t first_nonzero = 0;
  while (first_nonzero < 31U && be[first_nonzero] == 0U) {
    first_nonzero += 1U;
  }

  size_t payload_size = 32U - first_nonzero;
  if (payload_size == 1U && be[first_nonzero] <= 0x7fU) {
    out[0] = be[first_nonzero];
    return 1U;
  }

  out[0] = (uint8_t)(0x80U + payload_size);
  memcpy(out + 1U, be + first_nonzero, payload_size);
  return payload_size + 1U;
}

uint256_t derive_create_address_expected(uint64_t sender,
                                         const uint256_t *nonce) {
  uint8_t encoded_nonce[33];
  size_t nonce_size = encode_rlp_nonce(nonce, encoded_nonce);

  uint8_t payload[1 + 1 + 20 + 33];
  payload[0] = (uint8_t)(0xc0U + 1U + 20U + nonce_size);
  payload[1] = 0x94U;

  uint256_t sender_word = uint256_from_u64(sender);
  uint8_t sender_bytes[32];
  uint256_to_be_bytes(&sender_word, sender_bytes);
  memcpy(payload + 2U, sender_bytes + 12U, 20U);
  memcpy(payload + 22U, encoded_nonce, nonce_size);

  const union ethash_hash256 hash = ethash_keccak256(payload, 22U + nonce_size);
  uint8_t address_word[32] = {0};
  memcpy(address_word + 12U, hash.bytes + 12U, 20U);

  uint256_t out = uint256_zero();
  uint256_from_be_bytes(&out, address_word);
  return out;
}

void assert_gas_used_ok(const char *hex, uint64_t gas_limit,
                        uint64_t expected_used) {
  EVM_State vm;
  uint8_t *code = nullptr;
  EVM_Status status = execute_hex(hex, gas_limit, &vm, &code);
  assert(status == EVM_OK);
  assert(gas_limit >= expected_used);
  assert(vm.gas_remaining == gas_limit - expected_used);
  cleanup(&vm, code);
}
