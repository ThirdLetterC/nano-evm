#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>

#include "contracts.h"
#include "nano_utils.h"
#include "stack.h"
#include "uint256.h"

static int run_contract(const EVM_ContractSpec *spec) {
  uint8_t *code = nullptr;
  size_t code_size = 0;
  EVM_Status status = contracts_load_code(spec, &code, &code_size);
  if (status != EVM_OK) {
    fprintf(stderr, "[%s] code load failed: %s\n", spec->name,
            evm_status_string(status));
    return 1;
  }

  EVM_State vm;
  status = evm_init(&vm, code, code_size, spec->suggested_gas_limit);
  if (status != EVM_OK) {
    fprintf(stderr, "[%s] vm init failed: %s\n", spec->name,
            evm_status_string(status));
    free(code);
    return 1;
  }

  status = evm_execute(&vm);

  printf("[%s]\n", spec->name);
  printf("description: %s\n", spec->description);
  printf("status: %s\n", evm_status_string(status));
  printf("pc: %zu\n", vm.pc);
  printf("gas_remaining: %" PRIu64 "\n", vm.gas_remaining);
  printf("stack_depth: %zu\n", stack_depth(&vm.stack));
  printf("storage_count: %zu\n", vm.storage_count);
  printf("logs_count: %zu\n", vm.logs_count);

  uint256_t top = uint256_zero();
  if (stack_peek(&vm.stack, &top) == STACK_OK) {
    fputs("stack_top: ", stdout);
    nano_utils_print_uint256_hex(&top);
    fputc('\n', stdout);
  } else {
    puts("stack_top: <empty>");
  }

  if (vm.return_data_size > 0U) {
    fputs("return_data: ", stdout);
    nano_utils_print_bytes_hex(vm.return_data, vm.return_data_size);
    fputc('\n', stdout);
  } else {
    puts("return_data: <empty>");
  }
  fputc('\n', stdout);

  evm_destroy(&vm);
  free(code);
  return (status == EVM_OK) ? 0 : 2;
}

static int run_all_contracts() {
  size_t contract_count = 0;
  const EVM_ContractSpec *contracts = contracts_list(&contract_count);
  int result = 0;
  for (size_t i = 0; i < contract_count; ++i) {
    int contract_result = run_contract(&contracts[i]);
    if (contract_result != 0) {
      result = contract_result;
    }
  }
  return result;
}

static void print_available_contracts() {
  size_t contract_count = 0;
  const EVM_ContractSpec *contracts = contracts_list(&contract_count);
  puts("Available contracts:");
  for (size_t i = 0; i < contract_count; ++i) {
    printf("  %s: %s\n", contracts[i].name, contracts[i].description);
  }
}

int main(int argc, char **argv) {
  if (argc == 1) {
    return run_all_contracts();
  }

  int result = 0;
  for (int i = 1; i < argc; ++i) {
    const EVM_ContractSpec *spec = contracts_find(argv[i]);
    if (spec == nullptr) {
      fprintf(stderr, "Unknown contract: %s\n", argv[i]);
      print_available_contracts();
      result = 1;
      continue;
    }

    int contract_result = run_contract(spec);
    if (contract_result != 0) {
      result = contract_result;
    }
  }
  return result;
}
