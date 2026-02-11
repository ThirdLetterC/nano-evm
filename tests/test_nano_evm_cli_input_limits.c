#include "test_helpers.h"

#include <stdio.h>

typedef struct {
  int raw_status;
  char *stdout_text;
  char *stderr_text;
} evm_cli_result_t;

static constexpr size_t NANO_EVM_MAX_CLI_BYTECODE_BYTES = 32U * 1'024U;

static const char *nano_evm_path() {
  const char *path = getenv("NANO_EVM_PATH");
  if (path != nullptr && path[0] != '\0') {
    return path;
  }
  return "zig-out/bin/nano-evm";
}

[[nodiscard]] static char *read_text_file_alloc(const char *path) {
  FILE *file = fopen(path, "rb");
  assert(file != nullptr);

  assert(fseek(file, 0, SEEK_END) == 0);
  long end = ftell(file);
  assert(end >= 0);
  assert(fseek(file, 0, SEEK_SET) == 0);

  size_t size = (size_t)end;
  char *text = calloc(size + 1U, sizeof(char));
  assert(text != nullptr);
  size_t read = fread(text, sizeof(char), size, file);
  assert(read == size);
  text[size] = '\0';
  assert(fclose(file) == 0);
  return text;
}

[[nodiscard]] static char *make_hex_payload(size_t byte_count) {
  size_t hex_chars = 0U;
  assert(nano_utils_checked_mul_size(byte_count, 2U, &hex_chars));
  size_t hex_size = 0U;
  assert(nano_utils_checked_add_size(hex_chars, 3U, &hex_size));

  char *hex = calloc(hex_size, sizeof(char));
  assert(hex != nullptr);
  hex[0] = '0';
  hex[1] = 'x';
  memset(hex + 2U, '0', hex_chars);
  hex[2U + hex_chars] = '\0';
  return hex;
}

static evm_cli_result_t run_nano_evm(const char *bytecode_hex,
                                     const char *stdout_path,
                                     const char *stderr_path) {
  evm_cli_result_t result = {
      .raw_status = -1,
      .stdout_text = nullptr,
      .stderr_text = nullptr,
  };

  int command_len =
      snprintf(nullptr, 0, "\"%s\" \"%s\" > \"%s\" 2> \"%s\"", nano_evm_path(),
               bytecode_hex, stdout_path, stderr_path);
  assert(command_len > 0);

  size_t command_size = 0U;
  assert(nano_utils_checked_add_size((size_t)command_len, 1U, &command_size));
  char *command = calloc(command_size, sizeof(char));
  assert(command != nullptr);
  int written =
      snprintf(command, command_size, "\"%s\" \"%s\" > \"%s\" 2> \"%s\"",
               nano_evm_path(), bytecode_hex, stdout_path, stderr_path);
  assert(written == command_len);

  result.raw_status = system(command);
  free(command);
  assert(result.raw_status != -1);
  result.stdout_text = read_text_file_alloc(stdout_path);
  result.stderr_text = read_text_file_alloc(stderr_path);
  return result;
}

static void cleanup_cli_files(const char *stdout_path, const char *stderr_path,
                              evm_cli_result_t *result) {
  if (result != nullptr) {
    free(result->stdout_text);
    free(result->stderr_text);
    result->stdout_text = nullptr;
    result->stderr_text = nullptr;
  }
  assert(remove(stdout_path) == 0);
  assert(remove(stderr_path) == 0);
}

void test_nano_evm_rejects_oversized_cli_bytecode() {
  static const char *stdout_path = "/tmp/nano_evm_cli_limit.out";
  static const char *stderr_path = "/tmp/nano_evm_cli_limit.err";

  FILE *file = fopen(stdout_path, "wb");
  assert(file != nullptr);
  assert(fclose(file) == 0);
  file = fopen(stderr_path, "wb");
  assert(file != nullptr);
  assert(fclose(file) == 0);

  char *oversized_hex = make_hex_payload(NANO_EVM_MAX_CLI_BYTECODE_BYTES + 1U);
  evm_cli_result_t result =
      run_nano_evm(oversized_hex, stdout_path, stderr_path);
  assert(result.raw_status != 0);
  assert(strstr(result.stderr_text, "Bytecode exceeds max CLI input size") !=
         nullptr);

  free(oversized_hex);
  cleanup_cli_files(stdout_path, stderr_path, &result);
}
