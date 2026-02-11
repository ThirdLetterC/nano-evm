#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "evm.h"
#include "fuzz_input.h"

static constexpr size_t HEX_FUZZ_MAX_INPUT_BYTES = 1U * 1'024U * 1'024U;
static constexpr uint64_t HEX_FUZZ_GAS_LIMIT = 10'000U;

static void fuzz_hex_bytes(const uint8_t *data, size_t size) {
  if (data == nullptr && size != 0U) {
    return;
  }
  if (size > HEX_FUZZ_MAX_INPUT_BYTES) {
    return;
  }
  if (size > (SIZE_MAX - 1U)) {
    return;
  }

  size_t text_size = size + 1U;
  char *text = calloc(text_size, sizeof(char));
  if (text == nullptr) {
    return;
  }

  for (size_t i = 0; i < size; ++i) {
    // Preserve parser stress while guaranteeing NUL-terminated C input.
    text[i] = (data[i] == '\0') ? ' ' : (char)data[i];
  }
  text[size] = '\0';

  uint8_t *code = nullptr;
  size_t code_size = 0U;
  EVM_Status status = evm_load_hex(text, &code, &code_size);
  if (status == EVM_OK) {
    EVM_State vm;
    if (evm_init(&vm, code, code_size, HEX_FUZZ_GAS_LIMIT) == EVM_OK) {
      (void)evm_execute(&vm);
      evm_destroy(&vm);
    }
  }

  free(code);
  free(text);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  fuzz_hex_bytes(data, size);
  return 0;
}

int main(int argc, char **argv) {
  for (int i = 1; i < argc; ++i) {
    uint8_t *data = nullptr;
    size_t size = 0U;
    if (!fuzz_read_file_bounded(argv[i], HEX_FUZZ_MAX_INPUT_BYTES, &data,
                                &size)) {
      continue;
    }
    (void)LLVMFuzzerTestOneInput(data, size);
    free(data);
  }
  return 0;
}
