#ifndef EVM_CALL_AND_CREATE_INTERNAL_H
#define EVM_CALL_AND_CREATE_INTERNAL_H

#include "evm/gas_and_storage_internal.h"
#include "evm/return_data_internal.h"

EVM_Status execute_message_call(EVM_State *vm, uint8_t opcode,
                                uint64_t gas_forwarded,
                                const uint256_t *target,
                                const uint256_t *value,
                                const uint8_t *input_data, size_t input_size,
                                bool *out_success);
EVM_Status execute_create(EVM_State *vm, uint8_t opcode, uint64_t gas_forwarded,
                          uint64_t create_nonce, const uint8_t *init_code,
                          size_t init_code_size, const uint256_t *endowment,
                          const uint256_t *salt, uint256_t *out_address);

#endif
