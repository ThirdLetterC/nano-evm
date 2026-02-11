#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>

#include "evm.h"
#include "nano_utils.h"
#include "stack.h"
#include "uint256.h"

static constexpr size_t NANO_EVM_MAX_CLI_BYTECODE_BYTES = 32U * 1'024U;

static void print_usage(const char *prog) {
  fprintf(stderr, "Usage: %s <hex-bytecode> [gas-limit]\n", prog);
}

int main(int argc, char **argv) {
  if (argc < 2 || argc > 3) {
    print_usage(argv[0]);
    return 1;
  }

  constexpr uint64_t default_gas_limit = 100'000;
  uint64_t gas_limit = default_gas_limit;
  if (argc == 3) {
    if (!nano_utils_parse_u64(argv[2], &gas_limit)) {
      fprintf(stderr, "Invalid gas limit: %s\n", argv[2]);
      return 1;
    }
  }

  size_t decoded_bytecode_size = 0U;
  if (!nano_utils_hex_decoded_size(argv[1], &decoded_bytecode_size)) {
    fprintf(stderr, "Bytecode parse failed: %s\n",
            evm_status_string(EVM_ERR_HEX_PARSE));
    return 1;
  }
  if (decoded_bytecode_size > NANO_EVM_MAX_CLI_BYTECODE_BYTES) {
    fprintf(stderr, "Bytecode exceeds max CLI input size (%zu > %zu bytes)\n",
            decoded_bytecode_size, NANO_EVM_MAX_CLI_BYTECODE_BYTES);
    return 1;
  }

  uint8_t *code = nullptr;
  size_t code_size = 0;
  EVM_Status status = evm_load_hex(argv[1], &code, &code_size);
  if (status != EVM_OK) {
    fprintf(stderr, "Bytecode parse failed: %s\n", evm_status_string(status));
    return 1;
  }

  EVM_State vm;
  status = evm_init(&vm, code, code_size, gas_limit);
  if (status != EVM_OK) {
    fprintf(stderr, "VM init failed: %s\n", evm_status_string(status));
    free(code);
    return 1;
  }

  status = evm_execute(&vm);
  printf("status: %s\n", evm_status_string(status));
  printf("pc: %zu\n", vm.pc);
  printf("gas_remaining: %" PRIu64 "\n", vm.gas_remaining);
  printf("stack_depth: %zu\n", stack_depth(&vm.stack));

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

  evm_destroy(&vm);
  free(code);
  return (status == EVM_OK) ? 0 : 2;
}
