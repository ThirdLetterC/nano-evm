#include "test_helpers.h"

void test_nanosol_compiler_control_flow_and_storage() {
  static const char *source = "contract Counter {\n"
                              "  function main() {\n"
                              "    uint x = 0;\n"
                              "    uint i = 0;\n"
                              "    while (i < 5) {\n"
                              "      x = x + 2;\n"
                              "      i = i + 1;\n"
                              "    }\n"
                              "    if (x == 10) {\n"
                              "      sstore(0, x);\n"
                              "    } else {\n"
                              "      sstore(0, 0);\n"
                              "    }\n"
                              "    return sload(0);\n"
                              "  }\n"
                              "}\n";

  EVM_State vm;
  uint8_t *code = nullptr;
  EVM_Status status = execute_toy_source(source, 100'000, &vm, &code);
  assert(status == EVM_OK);
  assert_return_u64(&vm, 10);
  cleanup(&vm, code);
}

