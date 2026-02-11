#include "test_helpers.h"

static void assert_invalid_numeric_literal_source(const char *source) {
  uint8_t *code = nullptr;
  size_t code_size = 0U;
  char error[256] = {0};
  NanoSol_Status status =
      nanosol_compile(source, &code, &code_size, error, sizeof(error));
  assert(status == NANOSOL_ERR_PARSE);
  assert(code == nullptr);
  assert(code_size == 0U);
  assert(strstr(error, "invalid numeric literal") != nullptr);
}

void test_nanosol_compiler_numeric_literal_validation() {
  assert_invalid_numeric_literal_source(
      "contract C { function main() { return 1_; } }");
  assert_invalid_numeric_literal_source(
      "contract C { function main() { return 1__0; } }");
  assert_invalid_numeric_literal_source(
      "contract C { function main() { return 0x_ff; } }");
}
