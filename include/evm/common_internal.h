#ifndef EVM_COMMON_INTERNAL_H
#define EVM_COMMON_INTERNAL_H

#include "evm.h"
#include "evm/internal.h"
#include "opcodes.h"

int hex_value(char c);

EVM_Status charge_gas(EVM_State *vm, uint64_t amount);
EVM_Status out_of_gas(EVM_State *vm);
EVM_Status invalid_opcode(EVM_State *vm);
EVM_Status write_protection(EVM_State *vm);
uint64_t opcode_base_gas_cost(uint8_t opcode);

bool add_u64_overflow(uint64_t a, uint64_t b, uint64_t *out);
bool mul_u64_overflow(uint64_t a, uint64_t b, uint64_t *out);
uint64_t memory_cost_words(size_t words);

bool add_size_overflow(size_t a, size_t b, size_t *out);
bool mul_size_overflow(size_t a, size_t b, size_t *out);
EVM_Status reserve_realloc_array(void **buffer, size_t *capacity,
                                 size_t min_capacity, size_t element_size);

size_t hash_uint256_value(const uint256_t *value);
size_t hash_access_entry(const uint256_t *address, const uint256_t *key);

EVM_Status index_table_resize(size_t **table, size_t *capacity,
                              size_t count_hint);
EVM_Status storage_index_insert(EVM_State *vm, size_t index);
EVM_Status storage_index_rebuild(EVM_State *vm);
bool storage_find(const EVM_State *vm, const uint256_t *key,
                  size_t *out_index);

#endif
