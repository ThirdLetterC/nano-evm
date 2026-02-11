#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "evm.h"
#include "nano_utils.h"
#include "nanosol.h"
#include "opcodes.h"
#include "stack.h"
#include "uint256.h"

static constexpr size_t NANOSOL_SOURCE_MAX_BYTES = 4U * 1'024U * 1'024U;

static void print_usage(const char *prog) {
  fprintf(stderr, "Usage: %s <source.nsol> [--run] [gas-limit]\n", prog);
}

#define OPCODE_SIMPLE_MNEMONICS(X)                                             \
  X(STOP)                                                                      \
  X(ADD)                                                                       \
  X(MUL)                                                                       \
  X(SUB)                                                                       \
  X(DIV)                                                                       \
  X(SDIV)                                                                      \
  X(MOD)                                                                       \
  X(SMOD)                                                                      \
  X(ADDMOD)                                                                    \
  X(MULMOD)                                                                    \
  X(EXP)                                                                       \
  X(SIGNEXTEND)                                                                \
  X(LT)                                                                        \
  X(GT)                                                                        \
  X(SLT)                                                                       \
  X(SGT)                                                                       \
  X(EQ)                                                                        \
  X(ISZERO)                                                                    \
  X(AND)                                                                       \
  X(OR)                                                                        \
  X(XOR)                                                                       \
  X(NOT)                                                                       \
  X(BYTE)                                                                      \
  X(SHL)                                                                       \
  X(SHR)                                                                       \
  X(SAR)                                                                       \
  X(KECCAK256)                                                                 \
  X(ADDRESS)                                                                   \
  X(BALANCE)                                                                   \
  X(ORIGIN)                                                                    \
  X(CALLER)                                                                    \
  X(CALLVALUE)                                                                 \
  X(CALLDATALOAD)                                                              \
  X(CALLDATASIZE)                                                              \
  X(CALLDATACOPY)                                                              \
  X(CODESIZE)                                                                  \
  X(CODECOPY)                                                                  \
  X(GASPRICE)                                                                  \
  X(EXTCODESIZE)                                                               \
  X(EXTCODECOPY)                                                               \
  X(RETURNDATASIZE)                                                            \
  X(RETURNDATACOPY)                                                            \
  X(EXTCODEHASH)                                                               \
  X(BLOCKHASH)                                                                 \
  X(COINBASE)                                                                  \
  X(TIMESTAMP)                                                                 \
  X(NUMBER)                                                                    \
  X(PREVRANDAO)                                                                \
  X(GASLIMIT)                                                                  \
  X(CHAINID)                                                                   \
  X(SELFBALANCE)                                                               \
  X(BASEFEE)                                                                   \
  X(BLOBHASH)                                                                  \
  X(BLOBBASEFEE)                                                               \
  X(POP)                                                                       \
  X(MLOAD)                                                                     \
  X(MSTORE)                                                                    \
  X(MSTORE8)                                                                   \
  X(SLOAD)                                                                     \
  X(SSTORE)                                                                    \
  X(JUMP)                                                                      \
  X(JUMPI)                                                                     \
  X(PC)                                                                        \
  X(MSIZE)                                                                     \
  X(GAS)                                                                       \
  X(JUMPDEST)                                                                  \
  X(TLOAD)                                                                     \
  X(TSTORE)                                                                    \
  X(MCOPY)                                                                     \
  X(PUSH0)                                                                     \
  X(CREATE)                                                                    \
  X(CALL)                                                                      \
  X(CALLCODE)                                                                  \
  X(DELEGATECALL)                                                              \
  X(CREATE2)                                                                   \
  X(STATICCALL)                                                                \
  X(RETURN)                                                                    \
  X(REVERT)                                                                    \
  X(SELFDESTRUCT)

static const char *opcode_name(uint8_t opcode) {
  static const char *const mnemonic_map[UINT8_MAX + 1U] = {
#define OPCODE_MNEMONIC(name) [OPCODE_##name] = #name,
      OPCODE_SIMPLE_MNEMONICS(OPCODE_MNEMONIC)
#undef OPCODE_MNEMONIC
  };

  const char *mnemonic = mnemonic_map[opcode];
  if (mnemonic != nullptr) {
    return mnemonic;
  }

  if (opcode >= OPCODE_PUSH1 && opcode <= OPCODE_PUSH32) {
    return "PUSH";
  }
  if (opcode >= OPCODE_DUP1 && opcode <= OPCODE_DUP16) {
    return "DUP";
  }
  if (opcode >= OPCODE_SWAP1 && opcode <= OPCODE_SWAP16) {
    return "SWAP";
  }
  if (opcode >= OPCODE_LOG0 && opcode <= OPCODE_LOG4) {
    return "LOG";
  }
  return "UNKNOWN";
}

#undef OPCODE_SIMPLE_MNEMONICS

[[nodiscard]] static bool print_disassembly(const uint8_t *code,
                                            size_t code_size) {
  bool disassembly_ok = true;
  for (size_t pc = 0; pc < code_size; ++pc) {
    uint8_t opcode = code[pc];
    printf("%04zu  0x%02x  %s", pc, opcode, opcode_name(opcode));
    if (opcode >= OPCODE_PUSH1 && opcode <= OPCODE_PUSH32) {
      size_t immediate_size = (size_t)(opcode - OPCODE_PUSH1 + 1);
      printf("%zu ", immediate_size);
      fputs("0x", stdout);
      size_t available = code_size - (pc + 1U);
      size_t printed =
          (immediate_size <= available) ? immediate_size : available;
      for (size_t i = 0; i < printed; ++i) {
        printf("%02x", code[pc + 1U + i]);
      }
      if (printed < immediate_size) {
        fputs(" <truncated>", stdout);
        disassembly_ok = false;
      }
      pc += printed;
    }
    fputc('\n', stdout);
  }
  return disassembly_ok;
}

int main(int argc, char **argv) {
  if (argc < 2 || argc > 4) {
    print_usage(argv[0]);
    return 1;
  }

  bool run = false;
  bool gas_set = false;
  constexpr uint64_t default_gas_limit = 100'000;
  uint64_t gas_limit = default_gas_limit;

  for (int i = 2; i < argc; ++i) {
    if (strcmp(argv[i], "--run") == 0) {
      run = true;
      continue;
    }

    if (!nano_utils_parse_u64(argv[i], &gas_limit)) {
      fprintf(stderr, "Invalid argument: %s\n", argv[i]);
      print_usage(argv[0]);
      return 1;
    }
    gas_set = true;
  }

  if (gas_set && !run) {
    fputs("gas-limit requires --run\n", stderr);
    return 1;
  }

  char *source = nullptr;
  if (!nano_utils_read_file_text_limited(argv[1], NANOSOL_SOURCE_MAX_BYTES,
                                         &source)) {
    fprintf(stderr,
            "Failed to read file or exceeded max source size (%zu bytes): "
            "%s\n",
            NANOSOL_SOURCE_MAX_BYTES, argv[1]);
    return 1;
  }

  char error[256] = {0};
  uint8_t *code = nullptr;
  size_t code_size = 0;
  NanoSol_Status compile_status =
      nanosol_compile(source, &code, &code_size, error, sizeof(error));
  if (compile_status != NANOSOL_OK) {
    if (error[0] != '\0') {
      fprintf(stderr, "Compile failed: %s (%s)\n",
              nanosol_status_string(compile_status), error);
    } else {
      fprintf(stderr, "Compile failed: %s\n",
              nanosol_status_string(compile_status));
    }
    free(source);
    return 1;
  }

  char *hex = nullptr;
  if (nano_utils_bytes_to_hex(code, code_size, &hex) != NANO_UTILS_HEX_OK) {
    fputs("Failed to render hex output\n", stderr);
    free(code);
    free(source);
    return 1;
  }

  printf("bytecode_hex: %s\n", hex);
  puts("opcodes:");
  bool disassembly_ok = print_disassembly(code, code_size);
  if (!disassembly_ok) {
    fputs("warning: disassembly contains truncated PUSH immediates\n", stderr);
  }

  int result = 0;
  if (run) {
    EVM_State vm;
    EVM_Status status = evm_init(&vm, code, code_size, gas_limit);
    if (status != EVM_OK) {
      fprintf(stderr, "VM init failed: %s\n", evm_status_string(status));
      result = 1;
    } else {
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
      result = (status == EVM_OK) ? 0 : 2;
      evm_destroy(&vm);
    }
  }

  free(hex);
  free(code);
  free(source);
  return result;
}
