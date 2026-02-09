#include "test_helpers.h"

void test_precompile_dispatch() {
  EVM_State vm;
  uint8_t *code = nullptr;

  static const uint8_t identity_input[4] = {0xde, 0xad, 0xbe, 0xef};
  EVM_Status status = execute_hex_with_calldata(
      "6004600060003760046000600460005f600460fff160046000f3", identity_input,
      sizeof(identity_input), 5'000, &vm, &code);
  assert(status == EVM_OK);
  assert(vm.return_data != nullptr);
  assert(vm.return_data_size == sizeof(identity_input));
  assert(memcmp(vm.return_data, identity_input, sizeof(identity_input)) == 0);
  cleanup(&vm, code);

  status = execute_hex("60206000600060005f600260fff1600051", 5'000, &vm, &code);
  assert(status == EVM_OK);
  static const uint8_t sha256_empty[32] = {
      0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4,
      0xc8, 0x99, 0x6f, 0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b,
      0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55};
  assert_top_bytes32(&vm, sha256_empty);
  cleanup(&vm, code);

  status =
      execute_hex("60206000600060005f60036103e8f1600051", 5'000, &vm, &code);
  assert(status == EVM_OK);
  static const uint8_t ripemd160_empty[32] = {
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x9c, 0x11, 0x85, 0xa5, 0xc5, 0xe9, 0xfc, 0x54, 0x61, 0x28,
      0x08, 0x97, 0x7e, 0xe8, 0xf5, 0x48, 0xb2, 0x25, 0x8d, 0x31};
  assert_top_bytes32(&vm, ripemd160_empty);
  cleanup(&vm, code);

  status = execute_hex(
      "60016000526001602052600160405260026060536005606153600d6062536001601f"
      "606360005f60056103e8f1600051",
      20'000, &vm, &code);
  assert(status == EVM_OK);
  assert_top_u64(&vm, 6);
  cleanup(&vm, code);

  static const uint8_t ecrecover_digest[32] = {
      0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
      0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
      0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
  };
  static const uint8_t ecrecover_r[32] = {
      0x6e, 0xc2, 0xce, 0x72, 0xb2, 0xa1, 0xa2, 0x92, 0x21, 0xb4, 0xfd,
      0x39, 0xe8, 0x03, 0x8e, 0xc1, 0x38, 0x6b, 0xec, 0xce, 0x65, 0xf8,
      0x9f, 0x8a, 0xbb, 0xc1, 0xdf, 0xce, 0x59, 0xc2, 0xdb, 0xba,
  };
  static const uint8_t ecrecover_s[32] = {
      0xa7, 0x01, 0x94, 0x59, 0xa8, 0xbc, 0xf9, 0xa7, 0x07, 0x29, 0x37,
      0xa2, 0x94, 0x49, 0x46, 0x55, 0xfc, 0xd2, 0x6c, 0xe0, 0x8f, 0xc7,
      0xf2, 0xc4, 0x04, 0x63, 0xee, 0x56, 0xd6, 0x9e, 0x72, 0xf1,
  };
  static const uint8_t signer_pubkey_uncompressed[65] = {
      0x04, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0,
      0x62, 0x95, 0xce, 0x87, 0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d,
      0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17, 0x98,
      0x48, 0x3a, 0xda, 0x77, 0x26, 0xa3, 0xc4, 0x65, 0x5d, 0xa4, 0xfb,
      0xfc, 0x0e, 0x11, 0x08, 0xa8, 0xfd, 0x17, 0xb4, 0x48, 0xa6, 0x85,
      0x54, 0x19, 0x9c, 0x47, 0xd0, 0x8f, 0xfb, 0x10, 0xd4, 0xb8,
  };
  const union ethash_hash256 signer_hash =
      ethash_keccak256(signer_pubkey_uncompressed + 1U, 64U);
  uint8_t expected_address[20];
  memcpy(expected_address, signer_hash.bytes + 12U, sizeof(expected_address));

  uint8_t ecrecover_input[128] = {0};
  memcpy(ecrecover_input, ecrecover_digest, sizeof(ecrecover_digest));
  memcpy(ecrecover_input + 64U, ecrecover_r, sizeof(ecrecover_r));
  memcpy(ecrecover_input + 96U, ecrecover_s, sizeof(ecrecover_s));

  size_t matching_recoveries = 0U;
  for (uint8_t v = 27U; v <= 28U; ++v) {
    ecrecover_input[63] = v;
    status = execute_hex_with_calldata(
        "6080600060003760206000608060005f6001611f40f160206000f3",
        ecrecover_input, sizeof(ecrecover_input), 20'000, &vm, &code);
    assert(status == EVM_OK);
    assert(vm.return_data_size == 32U);
    if (memcmp(vm.return_data + 12U, expected_address,
               sizeof(expected_address)) == 0) {
      matching_recoveries += 1U;
    }
    cleanup(&vm, code);
  }
  assert(matching_recoveries == 1U);

  uint8_t bn256_add_input[128] = {0};
  bn256_add_input[64U + 31U] = 1U;
  bn256_add_input[96U + 31U] = 2U;
  status = execute_hex_with_calldata(
      "6080600060003760406000608060005f6006611f40f160406000f3", bn256_add_input,
      sizeof(bn256_add_input), 20'000, &vm, &code);
  assert(status == EVM_OK);
  assert(vm.return_data_size == 64U);
  for (size_t i = 0; i < 31U; ++i) {
    assert(vm.return_data[i] == 0U);
    assert(vm.return_data[32U + i] == 0U);
  }
  assert(vm.return_data[31] == 1U);
  assert(vm.return_data[63] == 2U);
  cleanup(&vm, code);

  uint8_t bn256_mul_input[96] = {0};
  bn256_mul_input[31] = 1U;
  bn256_mul_input[63] = 2U;
  bn256_mul_input[95] = 1U;
  status = execute_hex_with_calldata(
      "6060600060003760406000606060005f6007611f40f160406000f3", bn256_mul_input,
      sizeof(bn256_mul_input), 20'000, &vm, &code);
  assert(status == EVM_OK);
  assert(vm.return_data_size == 64U);
  for (size_t i = 0; i < 31U; ++i) {
    assert(vm.return_data[i] == 0U);
    assert(vm.return_data[32U + i] == 0U);
  }
  assert(vm.return_data[31] == 1U);
  assert(vm.return_data[63] == 2U);
  cleanup(&vm, code);

  uint8_t blake2f_input[213] = {0};
  blake2f_input[3] = 1U;
  status = execute_hex_with_calldata(
      "6100d56000600037604060006100d560005f6009612710f160406000f3",
      blake2f_input, sizeof(blake2f_input), 50'000, &vm, &code);
  assert(status == EVM_OK);
  assert(vm.return_data_size == 64U);
  bool nonzero_output = false;
  for (size_t i = 0; i < vm.return_data_size; ++i) {
    if (vm.return_data[i] != 0U) {
      nonzero_output = true;
      break;
    }
  }
  assert(nonzero_output);
  cleanup(&vm, code);

  uint8_t bn256_pairing_identity_input[192] = {0};
  status = execute_hex_with_calldata(
      "60c060006000376020600060c060005f6008620186a0f160206000f3",
      bn256_pairing_identity_input, sizeof(bn256_pairing_identity_input),
      200'000, &vm, &code);
  assert(status == EVM_OK);
  assert(vm.return_data_size == 32U);
  assert(vm.return_data[31] == 1U);
  cleanup(&vm, code);

  status = execute_hex("5f5f5f5f5f600960fff1", 5'000, &vm, &code);
  assert(status == EVM_OK);
  assert_top_u64(&vm, 0);
  cleanup(&vm, code);
}
