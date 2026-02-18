#pragma once

#include <stddef.h>
#include <stdint.h>

#include "evm.h"

typedef struct {
  const char *name;
  const char *description;
  const char *bytecode_hex;
  uint64_t suggested_gas_limit;
  EVM_Status expected_status;
} EVM_ContractSpec;

[[nodiscard]] const EVM_ContractSpec *contracts_list(size_t *out_count);
[[nodiscard]] const EVM_ContractSpec *contracts_find(const char *name);
[[nodiscard]] EVM_Status contracts_load_code(const EVM_ContractSpec *spec,
                                             uint8_t **out_code,
                                             size_t *out_size);
