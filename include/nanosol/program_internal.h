#pragma once

#include "nanosol/internal.h"

void compiler_init(NanoSol_Compiler *compiler, const char *source,
                   size_t source_length, char *error, size_t error_size);
bool compiler_parse_program(NanoSol_Compiler *compiler);
void compiler_destroy(NanoSol_Compiler *compiler);
