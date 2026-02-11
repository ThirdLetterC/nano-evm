#include "test_helpers.h"

#include <stdio.h>

typedef struct {
  int raw_status;
  char *stdout_text;
  char *stderr_text;
} node_cli_result_t;

static const char *nano_node_path() {
  const char *path = getenv("NANO_NODE_PATH");
  if (path != nullptr && path[0] != '\0') {
    return path;
  }
  return "zig-out/bin/nano-node";
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

static node_cli_result_t run_nano_node_inspect(const char *state_path,
                                               const char *stdout_path,
                                               const char *stderr_path) {
  node_cli_result_t result = {
      .raw_status = -1,
      .stdout_text = nullptr,
      .stderr_text = nullptr,
  };

  char command[2'048];
  int written = snprintf(command, sizeof(command),
                         "\"%s\" inspect --state \"%s\" > \"%s\" 2> \"%s\"",
                         nano_node_path(), state_path, stdout_path, stderr_path);
  assert(written > 0);
  assert((size_t)written < sizeof(command));

  result.raw_status = system(command);
  assert(result.raw_status != -1);
  result.stdout_text = read_text_file_alloc(stdout_path);
  result.stderr_text = read_text_file_alloc(stderr_path);
  return result;
}

static void cleanup_cli_files(const char *state_path, const char *stdout_path,
                              const char *stderr_path,
                              node_cli_result_t *result) {
  if (result != nullptr) {
    free(result->stdout_text);
    free(result->stderr_text);
    result->stdout_text = nullptr;
    result->stderr_text = nullptr;
  }

  assert(remove(state_path) == 0);
  assert(remove(stdout_path) == 0);
  assert(remove(stderr_path) == 0);
}

static void write_u32_le(FILE *file, uint32_t value) {
  uint8_t bytes[4] = {
      (uint8_t)(value & 0xffU),
      (uint8_t)((value >> 8U) & 0xffU),
      (uint8_t)((value >> 16U) & 0xffU),
      (uint8_t)((value >> 24U) & 0xffU),
  };
  assert(fwrite(bytes, sizeof(uint8_t), sizeof(bytes), file) == sizeof(bytes));
}

static void write_u64_le(FILE *file, uint64_t value) {
  uint8_t bytes[8] = {
      (uint8_t)(value & 0xffU),          (uint8_t)((value >> 8U) & 0xffU),
      (uint8_t)((value >> 16U) & 0xffU), (uint8_t)((value >> 24U) & 0xffU),
      (uint8_t)((value >> 32U) & 0xffU), (uint8_t)((value >> 40U) & 0xffU),
      (uint8_t)((value >> 48U) & 0xffU), (uint8_t)((value >> 56U) & 0xffU),
  };
  assert(fwrite(bytes, sizeof(uint8_t), sizeof(bytes), file) == sizeof(bytes));
}

static void write_zeros(FILE *file, size_t size) {
  uint8_t chunk[64] = {0};
  size_t remaining = size;
  while (remaining > 0U) {
    size_t to_write = (remaining > sizeof(chunk)) ? sizeof(chunk) : remaining;
    assert(fwrite(chunk, sizeof(uint8_t), to_write, file) == to_write);
    remaining -= to_write;
  }
}

static void write_state_header_v3(FILE *file, uint64_t code_size,
                                  uint64_t storage_count,
                                  uint64_t transient_count,
                                  uint64_t runtime_accounts_count) {
  static const uint8_t magic[8] = {'N', 'N', 'O', 'D', 'E', '0', '0', '1'};

  assert(fwrite(magic, sizeof(uint8_t), sizeof(magic), file) == sizeof(magic));
  write_u32_le(file, 3U);
  write_u32_le(file, 0U);
  write_zeros(file, 32U); // contract_address
  write_zeros(file, 32U); // self_balance
  write_u64_le(file, code_size);
  write_u64_le(file, storage_count);
  write_u64_le(file, transient_count);
  write_u64_le(file, runtime_accounts_count);
}

static void write_runtime_account_record(FILE *file, uint8_t flags) {
  write_zeros(file, 32U); // address
  write_zeros(file, 32U); // balance
  write_zeros(file, 32U); // code_hash
  write_zeros(file, 32U); // nonce (uint256 in v3)
  assert(fputc((int)flags, file) != EOF);
  write_u64_le(file, 0U); // code_size
  write_u64_le(file, 0U); // storage_count
  write_u64_le(file, 0U); // transient_count
}

void test_nano_node_rejects_oversized_code_state() {
  static const char *state_path = "/tmp/nano_node_state_oversized.bin";
  static const char *stdout_path = "/tmp/nano_node_state_oversized.out";
  static const char *stderr_path = "/tmp/nano_node_state_oversized.err";

  FILE *file = fopen(state_path, "wb");
  assert(file != nullptr);
  write_state_header_v3(file, 24'577U, 0U, 0U, 0U);
  assert(fclose(file) == 0);

  file = fopen(stdout_path, "wb");
  assert(file != nullptr);
  assert(fclose(file) == 0);
  file = fopen(stderr_path, "wb");
  assert(file != nullptr);
  assert(fclose(file) == 0);

  node_cli_result_t result =
      run_nano_node_inspect(state_path, stdout_path, stderr_path);
  assert(result.raw_status != 0);
  assert(strstr(result.stderr_text, "Contract bytecode too large") != nullptr);

  cleanup_cli_files(state_path, stdout_path, stderr_path, &result);
}

void test_nano_node_rejects_runtime_account_invalid_flags() {
  static const char *state_path = "/tmp/nano_node_state_invalid_flags.bin";
  static const char *stdout_path = "/tmp/nano_node_state_invalid_flags.out";
  static const char *stderr_path = "/tmp/nano_node_state_invalid_flags.err";

  FILE *file = fopen(state_path, "wb");
  assert(file != nullptr);
  write_state_header_v3(file, 0U, 0U, 0U, 1U);
  write_runtime_account_record(file, 0x80U);
  assert(fclose(file) == 0);

  file = fopen(stdout_path, "wb");
  assert(file != nullptr);
  assert(fclose(file) == 0);
  file = fopen(stderr_path, "wb");
  assert(file != nullptr);
  assert(fclose(file) == 0);

  node_cli_result_t result =
      run_nano_node_inspect(state_path, stdout_path, stderr_path);
  assert(result.raw_status != 0);
  assert(strstr(result.stderr_text, "Failed to read runtime accounts") !=
         nullptr);

  cleanup_cli_files(state_path, stdout_path, stderr_path, &result);
}
