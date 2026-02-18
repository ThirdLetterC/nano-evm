#pragma once

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "bn254_pairing.h"
#include "contracts.h"
#include "evm.h"
#include "keccak.h"
#include "nano_utils.h"
#include "nanosol.h"
#include "stack.h"
#include "uint256.h"

EVM_Status execute_hex(const char *hex, uint64_t gas_limit, EVM_State *vm,
                       uint8_t **code);
EVM_Status execute_hex_with_calldata(const char *hex, const uint8_t *call_data,
                                     size_t call_data_size, uint64_t gas_limit,
                                     EVM_State *vm, uint8_t **code);
void init_vm_from_hex(const char *hex, uint64_t gas_limit, EVM_State *vm,
                      uint8_t **code);
void cleanup(EVM_State *vm, uint8_t *code);
EVM_Status execute_toy_source(const char *source, uint64_t gas_limit,
                              EVM_State *vm, uint8_t **code);
void assert_top_u64(const EVM_State *vm, uint64_t expected);
void assert_top_bytes32(const EVM_State *vm, const uint8_t expected[32]);
void assert_return_u64(const EVM_State *vm, uint64_t expected);
uint256_t derive_create_address_expected(uint64_t sender,
                                         const uint256_t *nonce);
void assert_gas_used_ok(const char *hex, uint64_t gas_limit,
                        uint64_t expected_used);
