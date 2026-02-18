#pragma once

#include <ctype.h>
#include <errno.h>
#include <inttypes.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(__has_include)
#if __has_include(<stdckdint.h>)
#include <stdckdint.h>
#define NANO_UTILS_HAVE_STDCKDINT 1
#endif
#endif

#ifndef NANO_UTILS_HAVE_STDCKDINT
#define NANO_UTILS_HAVE_STDCKDINT 0
#endif

#include "uint256.h"

typedef enum {
  NANO_UTILS_HEX_OK = 0,
  NANO_UTILS_HEX_ERR_INVALID_ARGUMENT,
  NANO_UTILS_HEX_ERR_OVERFLOW,
  NANO_UTILS_HEX_ERR_ALLOC
} NanoUtilsHexStatus;

[[nodiscard]] [[maybe_unused]] static inline bool
nano_utils_checked_add_size(size_t a, size_t b, size_t *out) {
  if (out == nullptr) {
    return false;
  }
#if NANO_UTILS_HAVE_STDCKDINT
  return !ckd_add(out, a, b);
#else
  if (a > (SIZE_MAX - b)) {
    return false;
  }
  *out = a + b;
  return true;
#endif
}

[[nodiscard]] [[maybe_unused]] static inline bool
nano_utils_checked_mul_size(size_t a, size_t b, size_t *out) {
  if (out == nullptr) {
    return false;
  }
#if NANO_UTILS_HAVE_STDCKDINT
  return !ckd_mul(out, a, b);
#else
  if (a != 0U && b > (SIZE_MAX / a)) {
    return false;
  }
  *out = a * b;
  return true;
#endif
}

[[nodiscard]] [[maybe_unused]] static inline NanoUtilsHexStatus
nano_utils_bytes_to_hex(const uint8_t *bytes, size_t size, char **out_hex) {
  static const char HEX[] = "0123456789abcdef";
  if (out_hex == nullptr) {
    return NANO_UTILS_HEX_ERR_INVALID_ARGUMENT;
  }
  *out_hex = nullptr;
  if (size > 0U && bytes == nullptr) {
    return NANO_UTILS_HEX_ERR_INVALID_ARGUMENT;
  }

  size_t hex_size = 0U;
  if (!nano_utils_checked_mul_size(size, 2U, &hex_size)) {
    return NANO_UTILS_HEX_ERR_OVERFLOW;
  }

  size_t alloc_size = 0U;
  if (!nano_utils_checked_add_size(hex_size, 1U, &alloc_size)) {
    return NANO_UTILS_HEX_ERR_OVERFLOW;
  }

  char *hex = calloc(alloc_size, sizeof(char));
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
nano_utils_hex_decoded_size(const char *hex, size_t *out_size) {
  if (hex == nullptr || out_size == nullptr) {
    return false;
  }

  const unsigned char *cursor = (const unsigned char *)hex;
  while (*cursor != '\0' && isspace(*cursor)) {
    ++cursor;
  }
  if (cursor[0] == '0' && (cursor[1] == 'x' || cursor[1] == 'X')) {
    cursor += 2;
  }

  size_t nibble_count = 0U;
  bool saw_trailing_space = false;
  while (*cursor != '\0') {
    unsigned char c = *cursor;
    if (isspace(c)) {
      saw_trailing_space = true;
      ++cursor;
      continue;
    }
    if (saw_trailing_space) {
      return false;
    }

    bool is_hex_digit = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
                        (c >= 'A' && c <= 'F');
    if (!is_hex_digit) {
      return false;
    }
    if (nibble_count == SIZE_MAX) {
      return false;
    }
    nibble_count += 1U;
    ++cursor;
  }

  if ((nibble_count % 2U) != 0U) {
    return false;
  }
  *out_size = nibble_count / 2U;
  return true;
}

[[nodiscard]] [[maybe_unused]] static inline bool
nano_utils_read_file_text_limited(const char *path, size_t max_bytes,
                                  char **out_text) {
  if (path == nullptr || out_text == nullptr) {
    return false;
  }
  *out_text = nullptr;
  if (max_bytes > (SIZE_MAX - 1U)) {
    return false;
  }

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

  uintmax_t end_umax = (uintmax_t)end;
  if (end_umax > (uintmax_t)max_bytes) {
    fclose(file);
    return false;
  }
  if (end_umax > (uintmax_t)(SIZE_MAX - 1U)) {
    fclose(file);
    return false;
  }

  size_t size = (size_t)end_umax;
  size_t alloc_size = 0U;
  if (!nano_utils_checked_add_size(size, 1U, &alloc_size)) {
    fclose(file);
    return false;
  }

  char *text = calloc(alloc_size, sizeof(char));
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
nano_utils_read_file_text(const char *path, char **out_text) {
  return nano_utils_read_file_text_limited(path, SIZE_MAX - 1U, out_text);
}

[[nodiscard]] [[maybe_unused]] static inline bool
nano_utils_parse_u64(const char *text, uint64_t *out_value) {
  if (text == nullptr || out_value == nullptr) {
    return false;
  }

  const unsigned char *cursor = (const unsigned char *)text;
  while (*cursor != '\0' && isspace(*cursor)) {
    ++cursor;
  }
  if (*cursor == '\0' || *cursor == '-') {
    return false;
  }

  errno = 0;
  char *end = nullptr;
  uintmax_t parsed = strtoumax((const char *)cursor, &end, 0);
  if (errno != 0 || end == (char *)cursor || *end != '\0' ||
      parsed > UINT64_MAX) {
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

[[maybe_unused]] static inline void nano_utils_secure_zero(void *ptr,
                                                           size_t size) {
  if (ptr == nullptr || size == 0U) {
    return;
  }
  volatile uint8_t *bytes = (volatile uint8_t *)ptr;
  for (size_t i = 0; i < size; ++i) {
    bytes[i] = 0U;
  }
}
