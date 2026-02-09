#ifndef EVM_RETURN_DATA_INTERNAL_H
#define EVM_RETURN_DATA_INTERNAL_H

#include "evm/common_internal.h"

void clear_return_data(EVM_State *vm);

EVM_Status copy_memory_slice(EVM_State *vm, size_t offset, size_t size,
                             uint8_t **out_data);
EVM_Status set_return_data(EVM_State *vm, size_t offset, size_t size);
EVM_Status set_return_data_bytes(EVM_State *vm, const uint8_t *data,
                                 size_t size);
EVM_Status copy_return_data_to_memory(EVM_State *vm, size_t offset,
                                      size_t size);

bool size_to_u64(size_t value, uint64_t *out);
bool is_precompile_address(const uint256_t *address, uint8_t *out_id);
uint32_t load_be_u32(const uint8_t *in);
void sha256_hash(const uint8_t *data, size_t data_size, uint8_t out[32]);
void ripemd160_hash(const uint8_t *data, size_t data_size, uint8_t out[20]);
bool precompile_try_charge_gas(EVM_State *vm, uint64_t cost);
EVM_Status set_zero_return_data_bytes(EVM_State *vm, size_t size);

#endif
