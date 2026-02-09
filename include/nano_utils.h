#ifndef NANO_UTILS_H
#define NANO_UTILS_H

#include <errno.h>
#include <inttypes.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "uint256.h"

typedef enum {
  NANO_UTILS_HEX_OK = 0,
  NANO_UTILS_HEX_ERR_INVALID_ARGUMENT,
  NANO_UTILS_HEX_ERR_OVERFLOW,
  NANO_UTILS_HEX_ERR_ALLOC
} NanoUtilsHexStatus;

[[nodiscard]] [[maybe_unused]] static inline NanoUtilsHexStatus
nano_utils_bytes_to_hex(const uint8_t *bytes, size_t size, char **out_hex) {
  static const char HEX[] = "0123456789abcdef";
  if (out_hex == nullptr) {
    return NANO_UTILS_HEX_ERR_INVALID_ARGUMENT;
  }
  *out_hex = nullptr;

  if (size > (SIZE_MAX - 1U) / 2U) {
    return NANO_UTILS_HEX_ERR_OVERFLOW;
  }

  size_t hex_size = size * 2U;
  char *hex = calloc(hex_size + 1U, sizeof(char));
  if (hex == nullptr) {
    return NANO_UTILS_HEX_ERR_ALLOC;
  }

  for (size_t i = 0; i < size; ++i) {
    hex[i * 2U] = HEX[(bytes[i] >> 4U) & 0x0fU];
    hex[i * 2U + 1U] = HEX[bytes[i] & 0x0fU];
  }

  hex[hex_size] = '\0';
  *out_hex = hex;
  return NANO_UTILS_HEX_OK;
}

[[nodiscard]] [[maybe_unused]] static inline bool
nano_utils_read_file_text(const char *path, char **out_text) {
  if (path == nullptr || out_text == nullptr) {
    return false;
  }
  *out_text = nullptr;

  FILE *file = fopen(path, "rb");
  if (file == nullptr) {
    return false;
  }

  if (fseek(file, 0, SEEK_END) != 0) {
    fclose(file);
    return false;
  }

  long end = ftell(file);
  if (end < 0) {
    fclose(file);
    return false;
  }

  if (fseek(file, 0, SEEK_SET) != 0) {
    fclose(file);
    return false;
  }

  size_t size = (size_t)end;
  char *text = calloc(size + 1U, sizeof(char));
  if (text == nullptr) {
    fclose(file);
    return false;
  }

  size_t read = fread(text, sizeof(char), size, file);
  fclose(file);
  if (read != size) {
    free(text);
    return false;
  }

  text[size] = '\0';
  *out_text = text;
  return true;
}

[[nodiscard]] [[maybe_unused]] static inline bool
nano_utils_parse_u64(const char *text, uint64_t *out_value) {
  if (text == nullptr || out_value == nullptr) {
    return false;
  }

  errno = 0;
  char *end = nullptr;
  uintmax_t parsed = strtoumax(text, &end, 0);
  if (errno != 0 || end == text || *end != '\0' || parsed > UINT64_MAX) {
    return false;
  }

  *out_value = (uint64_t)parsed;
  return true;
}

[[maybe_unused]] static inline void
nano_utils_print_uint256_hex(const uint256_t *value) {
  uint8_t bytes[32];
  uint256_to_be_bytes(value, bytes);
  fputs("0x", stdout);
  for (size_t i = 0; i < sizeof(bytes); ++i) {
    printf("%02x", bytes[i]);
  }
}

[[maybe_unused]] static inline void
nano_utils_print_bytes_hex(const uint8_t *bytes, size_t size) {
  fputs("0x", stdout);
  for (size_t i = 0; i < size; ++i) {
    printf("%02x", bytes[i]);
  }
}

#endif
