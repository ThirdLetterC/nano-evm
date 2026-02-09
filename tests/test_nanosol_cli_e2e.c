#include "test_helpers.h"

#include <stdio.h>

static const char *nanosol_cli_path() {
  const char *path = getenv("NANO_SOLC_PATH");
  if (path != nullptr && path[0] != '\0') {
    return path;
  }
  return "zig-out/bin/nano-solc";
}

static void write_text_file_or_die(const char *path, const char *text) {
  FILE *file = fopen(path, "wb");
  assert(file != nullptr);
  size_t text_size = strlen(text);
  size_t written = fwrite(text, sizeof(char), text_size, file);
  assert(written == text_size);
  assert(fclose(file) == 0);
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

typedef struct {
  int raw_status;
  char *stdout_text;
  char *stderr_text;
} cli_result_t;

static cli_result_t run_nanosol_cli(const char *source_path,
                                    const char *extra_args,
                                    const char *stdout_path,
                                    const char *stderr_path) {
  cli_result_t result = {
      .raw_status = -1,
      .stdout_text = nullptr,
      .stderr_text = nullptr,
  };

  const char *args = (extra_args == nullptr) ? "" : extra_args;
  char command[2'048];
  int written =
      snprintf(command, sizeof(command), "\"%s\" \"%s\" %s > \"%s\" 2> \"%s\"",
               nanosol_cli_path(), source_path, args, stdout_path, stderr_path);
  assert(written > 0);
  assert((size_t)written < sizeof(command));

  result.raw_status = system(command);
  assert(result.raw_status != -1);
  result.stdout_text = read_text_file_alloc(stdout_path);
  result.stderr_text = read_text_file_alloc(stderr_path);
  return result;
}

static void cleanup_cli_files(const char *source_path, const char *stdout_path,
                              const char *stderr_path, cli_result_t *result) {
  if (result != nullptr) {
    free(result->stdout_text);
    free(result->stderr_text);
    result->stdout_text = nullptr;
    result->stderr_text = nullptr;
  }
  assert(remove(source_path) == 0);
  assert(remove(stdout_path) == 0);
  assert(remove(stderr_path) == 0);
}

void test_nanosol_cli_e2e_compile_success() {
  static const char *source_path = "/tmp/nanosol_cli_e2e_compile_ok.nsol";
  static const char *stdout_path = "/tmp/nanosol_cli_e2e_compile_ok.out";
  static const char *stderr_path = "/tmp/nanosol_cli_e2e_compile_ok.err";
  static const char *source = "contract CliOk {\n"
                              "  function main() {\n"
                              "    return 42;\n"
                              "  }\n"
                              "}\n";

  write_text_file_or_die(source_path, source);
  write_text_file_or_die(stdout_path, "");
  write_text_file_or_die(stderr_path, "");
  cli_result_t result =
      run_nanosol_cli(source_path, nullptr, stdout_path, stderr_path);
  assert(result.raw_status == 0);
  assert(strstr(result.stdout_text, "bytecode_hex: ") != nullptr);
  assert(strstr(result.stdout_text, "opcodes:") != nullptr);
  assert(strstr(result.stderr_text, "Compile failed:") == nullptr);
  cleanup_cli_files(source_path, stdout_path, stderr_path, &result);
}

void test_nanosol_cli_e2e_run_success() {
  static const char *source_path = "/tmp/nanosol_cli_e2e_run_ok.nsol";
  static const char *stdout_path = "/tmp/nanosol_cli_e2e_run_ok.out";
  static const char *stderr_path = "/tmp/nanosol_cli_e2e_run_ok.err";
  static const char *source = "contract CliRun {\n"
                              "  function main() {\n"
                              "    uint a = 2;\n"
                              "    uint b = 3;\n"
                              "    return a + b;\n"
                              "  }\n"
                              "}\n";

  write_text_file_or_die(source_path, source);
  write_text_file_or_die(stdout_path, "");
  write_text_file_or_die(stderr_path, "");
  cli_result_t result =
      run_nanosol_cli(source_path, "--run 50000", stdout_path, stderr_path);
  assert(result.raw_status == 0);
  assert(strstr(result.stdout_text, "status: OK") != nullptr);
  assert(strstr(result.stdout_text, "return_data: 0x") != nullptr);
  assert(strstr(result.stdout_text, "0000000000000005") != nullptr);
  assert(strstr(result.stderr_text, "Compile failed:") == nullptr);
  cleanup_cli_files(source_path, stdout_path, stderr_path, &result);
}

void test_nanosol_cli_e2e_compile_failure() {
  static const char *source_path = "/tmp/nanosol_cli_e2e_compile_fail.nsol";
  static const char *stdout_path = "/tmp/nanosol_cli_e2e_compile_fail.out";
  static const char *stderr_path = "/tmp/nanosol_cli_e2e_compile_fail.err";
  static const char *source = "contract Broken {\n"
                              "  function main() {\n"
                              "    x = 1;\n"
                              "  }\n"
                              "}\n";

  write_text_file_or_die(source_path, source);
  write_text_file_or_die(stdout_path, "");
  write_text_file_or_die(stderr_path, "");
  cli_result_t result =
      run_nanosol_cli(source_path, nullptr, stdout_path, stderr_path);
  assert(result.raw_status != 0);
  assert(strstr(result.stderr_text, "Compile failed: SEMANTIC_ERROR") !=
         nullptr);
  cleanup_cli_files(source_path, stdout_path, stderr_path, &result);
}
