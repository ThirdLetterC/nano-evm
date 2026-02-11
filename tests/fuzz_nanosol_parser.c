#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#include "evm.h"
#include "fuzz_input.h"
#include "nanosol.h"

static constexpr size_t NANOSOL_FUZZ_MAX_INPUT_BYTES = 1U * 1'024U * 1'024U;
static constexpr uint64_t NANOSOL_FUZZ_GAS_LIMIT = 10'000U;

static void fuzz_nanosol_bytes(const uint8_t *data, size_t size) {
  if (data == nullptr && size != 0U) {
    return;
  }
  if (size > NANOSOL_FUZZ_MAX_INPUT_BYTES) {
    return;
  }
  if (size > (SIZE_MAX - 1U)) {
    return;
  }

  size_t source_size = size + 1U;
  char *source = calloc(source_size, sizeof(char));
  if (source == nullptr) {
    return;
  }

  for (size_t i = 0; i < size; ++i) {
    // Avoid early termination so the parser sees the full buffer.
    source[i] = (data[i] == '\0') ? ' ' : (char)data[i];
  }
  source[size] = '\0';

  char error[256] = {0};
  uint8_t *bytecode = nullptr;
  size_t bytecode_size = 0U;
  NanoSol_Status compile_status =
      nanosol_compile(source, &bytecode, &bytecode_size, error, sizeof(error));
  if (compile_status == NANOSOL_OK && bytecode != nullptr) {
    EVM_State vm;
    if (evm_init(&vm, bytecode, bytecode_size, NANOSOL_FUZZ_GAS_LIMIT) ==
        EVM_OK) {
      (void)evm_execute(&vm);
      evm_destroy(&vm);
    }
  }
  nanosol_free(bytecode);

  char *hex = nullptr;
  (void)nanosol_compile_hex(source, &hex, error, sizeof(error));
  nanosol_free(hex);

  free(source);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  fuzz_nanosol_bytes(data, size);
  return 0;
}

int main(int argc, char **argv) {
  for (int i = 1; i < argc; ++i) {
    uint8_t *data = nullptr;
    size_t size = 0U;
    if (!fuzz_read_file_bounded(argv[i], NANOSOL_FUZZ_MAX_INPUT_BYTES, &data,
                                &size)) {
      continue;
    }
    (void)LLVMFuzzerTestOneInput(data, size);
    free(data);
  }
  return 0;
}
