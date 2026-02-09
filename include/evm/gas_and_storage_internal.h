#ifndef EVM_GAS_AND_STORAGE_INTERNAL_H
#define EVM_GAS_AND_STORAGE_INTERNAL_H

#include "evm/state_internal.h"

EVM_Status maybe_charge_sha3_word_gas(EVM_State *vm, size_t data_size);
EVM_Status maybe_charge_copy_word_gas(EVM_State *vm, size_t data_size);
EVM_Status maybe_charge_create2_hash_gas(EVM_State *vm, size_t init_code_size);
EVM_Status maybe_charge_initcode_word_gas(EVM_State *vm,
                                           size_t init_code_size);
EVM_Status maybe_charge_account_access_gas(EVM_State *vm,
                                           const uint256_t *address);
EVM_Status maybe_charge_selfdestruct_access_gas(EVM_State *vm,
                                                const uint256_t *address);
EVM_Status charge_call_extra_gas(EVM_State *vm, bool has_value_transfer,
                                 const uint256_t *new_account_target);

EVM_Status charge_call_forwarded_gas(EVM_State *vm,
                                     const uint256_t *requested_gas,
                                     bool has_value_transfer,
                                     uint64_t *out_forwarded_gas);
EVM_Status charge_create_forwarded_gas(EVM_State *vm,
                                       uint64_t *out_forwarded_gas);

EVM_Status maybe_charge_code_deposit_gas(EVM_State *vm, size_t code_size);
EVM_Status copy_to_memory(EVM_State *vm, size_t memory_offset,
                          size_t data_offset, size_t data_size,
                          const uint8_t *source, size_t source_size,
                          bool strict_bounds);
EVM_Status maybe_charge_exp_byte_gas(EVM_State *vm, const uint256_t *exponent);
EVM_Status maybe_apply_refund(EVM_State *vm);
EVM_Status sstore_berlin(EVM_State *vm, const uint256_t *key,
                         const uint256_t *new_value);
EVM_Status append_log(EVM_State *vm, const uint256_t topics[4],
                      size_t topics_count, const uint8_t *data,
                      size_t data_size);

#endif
