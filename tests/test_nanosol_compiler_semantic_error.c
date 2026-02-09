#include "test_helpers.h"

void test_nanosol_compiler_semantic_error() {
  static const char *source = "contract Broken {\n"
                              "  function main() {\n"
                              "    x = 1;\n"
                              "  }\n"
                              "}\n";

  uint8_t *code = nullptr;
  size_t code_size = 0;
  char error[256] = {0};
  NanoSol_Status status =
      nanosol_compile(source, &code, &code_size, error, sizeof(error));
  assert(status == NANOSOL_ERR_SEMANTIC);
  assert(code == nullptr);
  assert(code_size == 0);
  assert(error[0] != '\0');
}
