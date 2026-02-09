#include "test_helpers.h"

void test_nanosol_compiler_unterminated_block_comment() {
  static const char *source = "contract Broken {\n"
                              "  /* unterminated comment\n"
                              "  function main() {\n"
                              "    return 1;\n"
                              "  }\n"
                              "}\n";

  uint8_t *code = nullptr;
  size_t code_size = 0;
  char error[256] = {0};
  NanoSol_Status status =
      nanosol_compile(source, &code, &code_size, error, sizeof(error));
  assert(status == NANOSOL_ERR_LEX);
  assert(code == nullptr);
  assert(code_size == 0);
  assert(strstr(error, "unterminated block comment") != nullptr);
}

