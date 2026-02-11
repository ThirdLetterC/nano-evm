#include <ctype.h>
#include <stdlib.h>
#include <string.h>

#include "evm/common_internal.h"

EVM_Status evm_load_hex(const char *hex, uint8_t **out_code, size_t *out_size) {
  if (out_code == nullptr || out_size == nullptr) {
    return EVM_ERR_HEX_PARSE;
  }
  *out_code = nullptr;
  *out_size = 0;
  if (hex == nullptr) {
    return EVM_ERR_HEX_PARSE;
  }

  while (*hex != '\0' && isspace((unsigned char)*hex)) {
    ++hex;
  }

  if (hex[0] == '0' && (hex[1] == 'x' || hex[1] == 'X')) {
    hex += 2;
  }

  size_t nibble_count = 0U;
  bool saw_trailing_space = false;
  for (const char *cursor = hex; *cursor != '\0'; ++cursor) {
    unsigned char c = (unsigned char)*cursor;
    if (isspace(c)) {
      saw_trailing_space = true;
      continue;
    }
    if (saw_trailing_space) {
      return EVM_ERR_HEX_PARSE;
    }
    if (hex_value((char)c) < 0) {
      return EVM_ERR_HEX_PARSE;
    }
    if (nibble_count == SIZE_MAX) {
      return EVM_ERR_HEX_PARSE;
    }
    nibble_count += 1U;
  }

  if (nibble_count == 0U) {
    return EVM_OK;
  }
  if ((nibble_count % 2U) != 0U) {
    return EVM_ERR_HEX_PARSE;
  }

  size_t byte_len = nibble_count / 2U;
  uint8_t *code = calloc(byte_len, sizeof(uint8_t));
  if (code == nullptr) {
    return EVM_ERR_OOM;
  }

  size_t out_index = 0U;
  int hi_nibble = -1;
  saw_trailing_space = false;
  for (const char *cursor = hex; *cursor != '\0'; ++cursor) {
    unsigned char c = (unsigned char)*cursor;
    if (isspace(c)) {
      saw_trailing_space = true;
      continue;
    }
    if (saw_trailing_space) {
      free(code);
      return EVM_ERR_HEX_PARSE;
    }

    int value = hex_value((char)c);
    if (value < 0) {
      free(code);
      return EVM_ERR_HEX_PARSE;
    }

    if (hi_nibble < 0) {
      hi_nibble = value;
      continue;
    }

    if (out_index >= byte_len) {
      free(code);
      return EVM_ERR_HEX_PARSE;
    }
    code[out_index++] = (uint8_t)(((unsigned int)hi_nibble << 4U) |
                                  (unsigned int)value);
    hi_nibble = -1;
  }

  if (hi_nibble >= 0 || out_index != byte_len) {
    free(code);
    return EVM_ERR_HEX_PARSE;
  }

  *out_code = code;
  *out_size = byte_len;
  return EVM_OK;
}

const char *evm_status_string(EVM_Status status) {
  switch (status) {
  case EVM_OK:
    return "OK";
  case EVM_ERR_STACK_OVERFLOW:
    return "STACK_OVERFLOW";
  case EVM_ERR_STACK_UNDERFLOW:
    return "STACK_UNDERFLOW";
  case EVM_ERR_INVALID_OPCODE:
    return "INVALID_OPCODE";
  case EVM_ERR_INVALID_BYTECODE:
    return "INVALID_BYTECODE";
  case EVM_ERR_OUT_OF_GAS:
    return "OUT_OF_GAS";
  case EVM_ERR_WRITE_PROTECTION:
    return "WRITE_PROTECTION";
  case EVM_ERR_REVERT:
    return "REVERT";
  case EVM_ERR_HEX_PARSE:
    return "HEX_PARSE_ERROR";
  case EVM_ERR_RUNTIME:
    return "RUNTIME_ERROR";
  case EVM_ERR_INTERNAL:
    return "INTERNAL_ERROR";
  case EVM_ERR_OOM:
    return "OUT_OF_MEMORY";
  default:
    return "UNKNOWN";
  }
}
