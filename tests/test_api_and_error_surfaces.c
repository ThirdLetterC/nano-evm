#include "test_helpers.h"

#include <stdio.h>

void test_api_and_error_surfaces() {
  uint8_t *code = nullptr;
  size_t size = 0;

  EVM_Status status = evm_load_hex(" \t0X600A\n", &code, &size);
  assert(status == EVM_OK);
  assert(code != nullptr);
  assert(size == 2U);
  assert(code[0] == 0x60U);
  assert(code[1] == 0x0aU);
  free(code);

  code = nullptr;
  size = 999U;
  status = evm_load_hex("  \n\t", &code, &size);
  assert(status == EVM_OK);
  assert(code == nullptr);
  assert(size == 0U);

  status = evm_load_hex(nullptr, &code, &size);
  assert(status == EVM_ERR_HEX_PARSE);
  status = evm_load_hex("00", nullptr, &size);
  assert(status == EVM_ERR_HEX_PARSE);
  status = evm_load_hex("00", &code, nullptr);
  assert(status == EVM_ERR_HEX_PARSE);

  code = (uint8_t *)(uintptr_t)1U;
  size = 999U;
  status = evm_load_hex("0xzz", &code, &size);
  assert(status == EVM_ERR_HEX_PARSE);
  assert(code == nullptr);
  assert(size == 0U);

  uint64_t parsed_u64 = 0U;
  assert(!nano_utils_parse_u64("-1", &parsed_u64));
  assert(!nano_utils_parse_u64("   -2", &parsed_u64));
  assert(nano_utils_parse_u64("42", &parsed_u64));
  assert(parsed_u64 == 42U);
  assert(nano_utils_parse_u64("0x2a", &parsed_u64));
  assert(parsed_u64 == 42U);

  size_t decoded_hex_size = 0U;
  assert(nano_utils_hex_decoded_size("0x00ff", &decoded_hex_size));
  assert(decoded_hex_size == 2U);
  assert(nano_utils_hex_decoded_size("  0x00ff  \t", &decoded_hex_size));
  assert(decoded_hex_size == 2U);
  assert(!nano_utils_hex_decoded_size("0x0", &decoded_hex_size));
  assert(!nano_utils_hex_decoded_size("0x00 ff", &decoded_hex_size));

  static const char *limited_text_path = "/tmp/nano_utils_limited_read.txt";
  static const char *limited_text = "nano";
  FILE *limited_text_file = fopen(limited_text_path, "wb");
  assert(limited_text_file != nullptr);
  assert(fwrite(limited_text, sizeof(char), strlen(limited_text),
                limited_text_file) == strlen(limited_text));
  assert(fclose(limited_text_file) == 0);

  char *limited_read = (char *)(uintptr_t)1U;
  assert(
      !nano_utils_read_file_text_limited(limited_text_path, 3U, &limited_read));
  assert(limited_read == nullptr);
  assert(
      nano_utils_read_file_text_limited(limited_text_path, 4U, &limited_read));
  assert(limited_read != nullptr);
  assert(strcmp(limited_read, limited_text) == 0);
  free(limited_read);
  assert(remove(limited_text_path) == 0);

  assert(strcmp(evm_status_string(EVM_OK), "OK") == 0);
  assert(strcmp(evm_status_string(EVM_ERR_OOM), "OUT_OF_MEMORY") == 0);
  assert(strcmp(evm_status_string((EVM_Status)999), "UNKNOWN") == 0);

  EVM_State vm;
  status = evm_init(nullptr, nullptr, 0U, 10U);
  assert(status == EVM_ERR_INVALID_BYTECODE);
  status = evm_init(&vm, nullptr, 1U, 10U);
  assert(status == EVM_ERR_INVALID_BYTECODE);
  status = evm_init(&vm, nullptr, 0U, 10U);
  assert(status == EVM_OK);
  evm_destroy(&vm);
  evm_destroy(nullptr);

  status = execute_hex("600456605b00", 100U, &vm, &code);
  assert(status == EVM_ERR_INVALID_OPCODE);
  cleanup(&vm, code);

  size_t contract_count = 0;
  const EVM_ContractSpec *contracts = contracts_list(&contract_count);
  assert(contracts != nullptr);
  assert(contract_count > 0U);

  EVM_ContractSpec invalid_spec = {
      .name = "invalid",
      .description = "invalid",
      .bytecode_hex = nullptr,
      .suggested_gas_limit = 1U,
  };
  size = 0U;
  code = nullptr;
  assert(contracts_load_code(nullptr, &code, &size) ==
         EVM_ERR_INVALID_BYTECODE);
  assert(contracts_load_code(&invalid_spec, &code, &size) ==
         EVM_ERR_INVALID_BYTECODE);
  assert(contracts_load_code(contracts, nullptr, &size) ==
         EVM_ERR_INVALID_BYTECODE);
  assert(contracts_load_code(contracts, &code, nullptr) ==
         EVM_ERR_INVALID_BYTECODE);

  char *hex = nullptr;
  char error[256] = {0};
  assert(nanosol_compile_hex(nullptr, &hex, error, sizeof(error)) ==
         NANOSOL_ERR_INVALID_ARGUMENT);
  assert(hex == nullptr);

  assert(nanosol_compile_hex("contract C { function main() { return 1; } }",
                             &hex, error, sizeof(error)) == NANOSOL_OK);
  assert(hex != nullptr);
  assert(strlen(hex) > 0U);
  nanosol_free(hex);
  hex = nullptr;

  assert(nanosol_compile_hex("contract Broken { function main() { x = 1; } }",
                             &hex, error,
                             sizeof(error)) == NANOSOL_ERR_SEMANTIC);
  assert(hex == nullptr);
  assert(error[0] != '\0');

  assert(nanosol_compile_hex("contract C {}", nullptr, error, sizeof(error)) ==
         NANOSOL_ERR_INVALID_ARGUMENT);

  assert(strcmp(nanosol_status_string(NANOSOL_OK), "OK") == 0);
  assert(strcmp(nanosol_status_string(NANOSOL_ERR_RUNTIME_INTERNAL),
                "RUNTIME_INTERNAL_ERROR") == 0);
  assert(strcmp(nanosol_status_string((NanoSol_Status)999), "UNKNOWN_ERROR") ==
         0);

  nanosol_free(nullptr);
}
