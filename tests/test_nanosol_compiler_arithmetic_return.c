#include "test_helpers.h"

void test_nanosol_compiler_arithmetic_return() {
  static const char *source = "contract SimpleMath {\n"
                              "  function main() {\n"
                              "    uint a = 2;\n"
                              "    uint b = 3;\n"
                              "    return a + b;\n"
                              "  }\n"
                              "}\n";

  EVM_State vm;
  uint8_t *code = nullptr;
  EVM_Status status = execute_toy_source(source, 2'000, &vm, &code);
  assert(status == EVM_OK);
  assert_return_u64(&vm, 5);
  cleanup(&vm, code);
}
