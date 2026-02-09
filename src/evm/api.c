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

  size_t len = strlen(hex);
  while (len > 0) {
    unsigned char c = (unsigned char)hex[len - 1U];
    if (c == ' ' || (c >= '\t' && c <= '\r')) {
      --len;
      continue;
    }
    break;
  }
  if (len == 0) {
    return EVM_OK;
  }
  if (len % 2U != 0) {
    return EVM_ERR_HEX_PARSE;
  }

  size_t byte_len = len / 2U;
  uint8_t *code = calloc(byte_len, sizeof(uint8_t));
  if (code == nullptr) {
    return EVM_ERR_OOM;
  }

  for (size_t i = 0; i < byte_len; ++i) {
    int hi = hex_value(hex[i * 2U]);
    int lo = hex_value(hex[i * 2U + 1U]);
    if (hi < 0 || lo < 0) {
      free(code);
      return EVM_ERR_HEX_PARSE;
    }
    code[i] = (uint8_t)((hi << 4) | lo);
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
