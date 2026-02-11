#include "test_helpers.h"

#include <stdio.h>

typedef struct {
  int raw_status;
  char *stdout_text;
  char *stderr_text;
} node_cli_result_t;

static constexpr size_t NODE_CALLDATA_MAX_BYTES = 32U * 1'024U;

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

static node_cli_result_t run_nano_node_command(const char *args,
                                               const char *stdout_path,
                                               const char *stderr_path) {
  node_cli_result_t result = {
      .raw_status = -1,
      .stdout_text = nullptr,
      .stderr_text = nullptr,
  };

  int command_len = snprintf(nullptr, 0, "\"%s\" %s > \"%s\" 2> \"%s\"",
                             nano_node_path(), args, stdout_path, stderr_path);
  assert(command_len > 0);

  size_t command_size = 0U;
  assert(nano_utils_checked_add_size((size_t)command_len, 1U, &command_size));
  char *command = calloc(command_size, sizeof(char));
  assert(command != nullptr);
  int written = snprintf(command, command_size, "\"%s\" %s > \"%s\" 2> \"%s\"",
                         nano_node_path(), args, stdout_path, stderr_path);
  assert(written == command_len);

  result.raw_status = system(command);
  free(command);
  assert(result.raw_status != -1);
  result.stdout_text = read_text_file_alloc(stdout_path);
  result.stderr_text = read_text_file_alloc(stderr_path);
  return result;
}

static node_cli_result_t run_nano_node_inspect(const char *state_path,
                                               const char *stdout_path,
                                               const char *stderr_path) {
  int args_len = snprintf(nullptr, 0, "inspect --state \"%s\"", state_path);
  assert(args_len > 0);

  size_t args_size = 0U;
  assert(nano_utils_checked_add_size((size_t)args_len, 1U, &args_size));
  char *args = calloc(args_size, sizeof(char));
  assert(args != nullptr);
  int written = snprintf(args, args_size, "inspect --state \"%s\"", state_path);
  assert(written == args_len);

  node_cli_result_t result =
      run_nano_node_command(args, stdout_path, stderr_path);
  free(args);
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

static void write_stop_code_state(const char *state_path) {
  FILE *file = fopen(state_path, "wb");
  assert(file != nullptr);
  write_state_header_v3(file, 1U, 0U, 0U, 0U);
  assert(fputc(0x00, file) != EOF);
  assert(fclose(file) == 0);
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

void test_nano_node_call_rejects_oversized_calldata_hex() {
  static const char *state_path = "/tmp/nano_node_call_calldata_limit.bin";
  static const char *stdout_path = "/tmp/nano_node_call_calldata_limit.out";
  static const char *stderr_path = "/tmp/nano_node_call_calldata_limit.err";

  write_stop_code_state(state_path);

  FILE *file = fopen(stdout_path, "wb");
  assert(file != nullptr);
  assert(fclose(file) == 0);
  file = fopen(stderr_path, "wb");
  assert(file != nullptr);
  assert(fclose(file) == 0);

  char *oversized_hex = make_hex_payload(NODE_CALLDATA_MAX_BYTES + 1U);
  int args_len = snprintf(nullptr, 0, "call --state \"%s\" --calldata \"%s\"",
                          state_path, oversized_hex);
  assert(args_len > 0);

  size_t args_size = 0U;
  assert(nano_utils_checked_add_size((size_t)args_len, 1U, &args_size));
  char *args = calloc(args_size, sizeof(char));
  assert(args != nullptr);
  int written =
      snprintf(args, args_size, "call --state \"%s\" --calldata \"%s\"",
               state_path, oversized_hex);
  assert(written == args_len);

  node_cli_result_t result =
      run_nano_node_command(args, stdout_path, stderr_path);
  assert(result.raw_status != 0);
  assert(strstr(result.stderr_text, "Calldata exceeds max size") != nullptr);

  free(args);
  free(oversized_hex);
  cleanup_cli_files(state_path, stdout_path, stderr_path, &result);
}

void test_nano_node_call_rejects_oversized_command_word_index() {
  static const char *state_path = "/tmp/nano_node_call_arg_limit.bin";
  static const char *stdout_path = "/tmp/nano_node_call_arg_limit.out";
  static const char *stderr_path = "/tmp/nano_node_call_arg_limit.err";

  write_stop_code_state(state_path);

  FILE *file = fopen(stdout_path, "wb");
  assert(file != nullptr);
  assert(fclose(file) == 0);
  file = fopen(stderr_path, "wb");
  assert(file != nullptr);
  assert(fclose(file) == 0);

  int args_len = snprintf(nullptr, 0, "call --state \"%s\" --cmd 1 --arg1024 0",
                          state_path);
  assert(args_len > 0);

  size_t args_size = 0U;
  assert(nano_utils_checked_add_size((size_t)args_len, 1U, &args_size));
  char *args = calloc(args_size, sizeof(char));
  assert(args != nullptr);
  int written = snprintf(args, args_size,
                         "call --state \"%s\" --cmd 1 --arg1024 0", state_path);
  assert(written == args_len);

  node_cli_result_t result =
      run_nano_node_command(args, stdout_path, stderr_path);
  assert(result.raw_status != 0);
  assert(strstr(result.stderr_text, "Command calldata exceeds max size") !=
         nullptr);

  free(args);
  cleanup_cli_files(state_path, stdout_path, stderr_path, &result);
}

void test_nano_node_call_rejects_oversized_command_word_hex() {
  static const char *state_path = "/tmp/nano_node_call_cmd_word_limit.bin";
  static const char *stdout_path = "/tmp/nano_node_call_cmd_word_limit.out";
  static const char *stderr_path = "/tmp/nano_node_call_cmd_word_limit.err";

  write_stop_code_state(state_path);

  FILE *file = fopen(stdout_path, "wb");
  assert(file != nullptr);
  assert(fclose(file) == 0);
  file = fopen(stderr_path, "wb");
  assert(file != nullptr);
  assert(fclose(file) == 0);

  char *oversized_cmd_word = make_hex_payload(33U);
  int args_len = snprintf(nullptr, 0, "call --state \"%s\" --cmd \"%s\"",
                          state_path, oversized_cmd_word);
  assert(args_len > 0);

  size_t args_size = 0U;
  assert(nano_utils_checked_add_size((size_t)args_len, 1U, &args_size));
  char *args = calloc(args_size, sizeof(char));
  assert(args != nullptr);
  int written = snprintf(args, args_size, "call --state \"%s\" --cmd \"%s\"",
                         state_path, oversized_cmd_word);
  assert(written == args_len);

  node_cli_result_t result =
      run_nano_node_command(args, stdout_path, stderr_path);
  assert(result.raw_status != 0);
  assert(strstr(result.stderr_text, "Word too wide (>32 bytes)") != nullptr);

  free(args);
  free(oversized_cmd_word);
  cleanup_cli_files(state_path, stdout_path, stderr_path, &result);
}
