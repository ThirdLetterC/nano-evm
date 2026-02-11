#include <stdio.h>
#include <stdlib.h>

#include "nano_utils.h"
#include "nanosol/common_internal.h"
#include "nanosol/program_internal.h"

static bool nanosol_source_length_bounded(const char *source,
                                          size_t *out_source_length) {
  if (source == nullptr || out_source_length == nullptr) {
    return false;
  }

  size_t length = 0U;
  while (length <= NANOSOL_MAX_SOURCE_SIZE) {
    if (source[length] == '\0') {
      *out_source_length = length;
      return true;
    }
    length += 1U;
  }
  return false;
}

NanoSol_Status nanosol_compile(const char *source, uint8_t **out_bytecode,
                               size_t *out_size, char *out_error,
                               size_t out_error_size) {
  if (source == nullptr || out_bytecode == nullptr || out_size == nullptr) {
    return NANOSOL_ERR_INVALID_ARGUMENT;
  }

  *out_bytecode = nullptr;
  *out_size = 0;
  if (out_error != nullptr && out_error_size > 0) {
    out_error[0] = '\0';
  }

  size_t source_length = 0U;
  if (!nanosol_source_length_bounded(source, &source_length)) {
    if (out_error != nullptr && out_error_size > 0) {
      (void)snprintf(
          out_error, out_error_size,
          "source exceeds maximum size (%zu bytes) or is not NUL-terminated",
          NANOSOL_MAX_SOURCE_SIZE);
    }
    return NANOSOL_ERR_INVALID_ARGUMENT;
  }

  NanoSol_Compiler compiler;
  compiler_init(&compiler, source, source_length, out_error, out_error_size);

  bool parsed = compiler_parse_program(&compiler);
  if (parsed && compiler.status == NANOSOL_OK) {
    // Resolve all deferred jump-label placeholders after final code layout.
    parsed = compiler_patch_labels(&compiler);
  }

  if (!parsed || compiler.status != NANOSOL_OK) {
    NanoSol_Status status =
        (compiler.status == NANOSOL_OK) ? NANOSOL_ERR_PARSE : compiler.status;
    compiler_destroy(&compiler);
    return status;
  }

  // Transfer bytecode ownership to caller; compiler_destroy must not free it.
  *out_bytecode = compiler.bytecode.bytes;
  *out_size = compiler.bytecode.size;
  compiler.bytecode.bytes = nullptr;
  compiler.bytecode.size = 0;
  compiler.bytecode.capacity = 0;
  compiler_destroy(&compiler);
  return NANOSOL_OK;
}

NanoSol_Status nanosol_compile_hex(const char *source, char **out_hex,
                                   char *out_error, size_t out_error_size) {
  if (out_hex == nullptr) {
    return NANOSOL_ERR_INVALID_ARGUMENT;
  }
  *out_hex = nullptr;

  uint8_t *bytecode = nullptr;
  size_t bytecode_size = 0;
  NanoSol_Status status = nanosol_compile(source, &bytecode, &bytecode_size,
                                          out_error, out_error_size);
  if (status != NANOSOL_OK) {
    return status;
  }

  NanoUtilsHexStatus hex_status =
      nano_utils_bytes_to_hex(bytecode, bytecode_size, out_hex);
  if (hex_status == NANO_UTILS_HEX_ERR_INVALID_ARGUMENT) {
    status = NANOSOL_ERR_INVALID_ARGUMENT;
  } else if (hex_status == NANO_UTILS_HEX_ERR_OVERFLOW) {
    status = NANOSOL_ERR_RUNTIME_INTERNAL;
  } else if (hex_status == NANO_UTILS_HEX_ERR_ALLOC) {
    status = NANOSOL_ERR_RUNTIME_ALLOC;
  } else {
    status = NANOSOL_OK;
  }
  free(bytecode);
  if (status != NANOSOL_OK && out_error != nullptr && out_error_size > 0) {
    (void)snprintf(out_error, out_error_size,
                   "failed to convert bytecode to hex");
  }
  return status;
}

const char *nanosol_status_string(NanoSol_Status status) {
  switch (status) {
  case NANOSOL_OK:
    return "OK";
  case NANOSOL_ERR_INVALID_ARGUMENT:
    return "INVALID_ARGUMENT";
  case NANOSOL_ERR_LEX:
    return "LEX_ERROR";
  case NANOSOL_ERR_PARSE:
    return "PARSE_ERROR";
  case NANOSOL_ERR_SEMANTIC:
    return "SEMANTIC_ERROR";
  case NANOSOL_ERR_EMIT:
    return "EMIT_ERROR";
  case NANOSOL_ERR_COMPILE_ALLOC:
    return "COMPILE_ALLOC_ERROR";
  case NANOSOL_ERR_COMPILE_INTERNAL:
    return "COMPILE_INTERNAL_ERROR";
  case NANOSOL_ERR_RUNTIME_ALLOC:
    return "RUNTIME_ALLOC_ERROR";
  case NANOSOL_ERR_RUNTIME_INTERNAL:
    return "RUNTIME_INTERNAL_ERROR";
  default:
    return "UNKNOWN_ERROR";
  }
}

void nanosol_free(void *ptr) { free(ptr); }
