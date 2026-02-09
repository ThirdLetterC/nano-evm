#ifndef NANOSOL_H
#define NANOSOL_H

#include <stddef.h>
#include <stdint.h>

typedef enum {
  NANOSOL_OK = 0,
  NANOSOL_ERR_INVALID_ARGUMENT,
  NANOSOL_ERR_LEX,
  NANOSOL_ERR_PARSE,
  NANOSOL_ERR_SEMANTIC,
  NANOSOL_ERR_EMIT,
  NANOSOL_ERR_COMPILE_ALLOC,
  NANOSOL_ERR_COMPILE_INTERNAL,
  NANOSOL_ERR_RUNTIME_ALLOC,
  NANOSOL_ERR_RUNTIME_INTERNAL
} NanoSol_Status;

[[nodiscard]] NanoSol_Status nanosol_compile(const char *source,
                                             uint8_t **out_bytecode,
                                             size_t *out_size, char *out_error,
                                             size_t out_error_size);
[[nodiscard]] NanoSol_Status nanosol_compile_hex(const char *source,
                                                 char **out_hex,
                                                 char *out_error,
                                                 size_t out_error_size);

[[nodiscard]] const char *nanosol_status_string(NanoSol_Status status);
void nanosol_free(void *ptr);

#endif
