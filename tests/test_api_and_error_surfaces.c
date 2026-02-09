#include "test_helpers.h"

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
                             &hex, error, sizeof(error)) ==
         NANOSOL_ERR_SEMANTIC);
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
