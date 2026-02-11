#include <limits.h>
#include <stdlib.h>
#include <string.h>

#if defined(__has_include)
#if __has_include(<stdckdint.h>)
#include <stdckdint.h>
#define NANO_EVM_HAVE_STDCKDINT 1
#endif
#endif

#ifndef NANO_EVM_HAVE_STDCKDINT
#define NANO_EVM_HAVE_STDCKDINT 0
#endif

#include "evm/common_internal.h"

int hex_value(char c) {
  if (c >= '0' && c <= '9') {
    return c - '0';
  }
  if (c >= 'a' && c <= 'f') {
    return 10 + (c - 'a');
  }
  if (c >= 'A' && c <= 'F') {
    return 10 + (c - 'A');
  }
  return -1;
}

EVM_Status charge_gas(EVM_State *vm, uint64_t amount) {
  if (vm->gas_remaining < amount) {
    return out_of_gas(vm);
  }
  vm->gas_remaining -= amount;
  return EVM_OK;
}

EVM_Status out_of_gas(EVM_State *vm) {
  if (vm != nullptr) {
    vm->gas_remaining = 0;
  }
  return EVM_ERR_OUT_OF_GAS;
}

EVM_Status invalid_opcode(EVM_State *vm) {
  vm->gas_remaining = 0;
  return EVM_ERR_INVALID_OPCODE;
}

EVM_Status write_protection(EVM_State *vm) {
  vm->gas_remaining = 0;
  return EVM_ERR_WRITE_PROTECTION;
}

uint64_t opcode_base_gas_cost(uint8_t opcode) {
  if (opcode >= OPCODE_DUP1 && opcode <= OPCODE_DUP16) {
    return GAS_VERYLOW;
  }
  if (opcode >= OPCODE_SWAP1 && opcode <= OPCODE_SWAP16) {
    return GAS_VERYLOW;
  }
  if (opcode >= OPCODE_PUSH1 && opcode <= OPCODE_PUSH32) {
    return GAS_VERYLOW;
  }

  switch (opcode) {
  case OPCODE_STOP:
    return GAS_ZERO;
  case OPCODE_POP:
    return GAS_BASE;
  case OPCODE_ADD:
  case OPCODE_SUB:
  case OPCODE_LT:
  case OPCODE_GT:
  case OPCODE_SLT:
  case OPCODE_SGT:
  case OPCODE_EQ:
  case OPCODE_ISZERO:
  case OPCODE_AND:
  case OPCODE_OR:
  case OPCODE_XOR:
  case OPCODE_NOT:
  case OPCODE_BYTE:
  case OPCODE_SHL:
  case OPCODE_SHR:
  case OPCODE_SAR:
    return GAS_VERYLOW;
  case OPCODE_MUL:
  case OPCODE_DIV:
  case OPCODE_SDIV:
  case OPCODE_MOD:
  case OPCODE_SMOD:
  case OPCODE_SIGNEXTEND:
    return GAS_LOW;
  case OPCODE_ADDMOD:
  case OPCODE_MULMOD:
    return GAS_MID;
  case OPCODE_EXP:
    return GAS_HIGH;
  case OPCODE_KECCAK256:
    return 0;
  case OPCODE_ADDRESS:
  case OPCODE_ORIGIN:
  case OPCODE_CALLER:
  case OPCODE_CALLVALUE:
    return GAS_BASE;
  case OPCODE_BALANCE:
    return GAS_EXTERNAL;
  case OPCODE_CALLDATALOAD:
    return GAS_VERYLOW;
  case OPCODE_CALLDATASIZE:
    return GAS_BASE;
  case OPCODE_CALLDATACOPY:
    return GAS_VERYLOW;
  case OPCODE_CODESIZE:
    return GAS_BASE;
  case OPCODE_CODECOPY:
    return GAS_VERYLOW;
  case OPCODE_GASPRICE:
    return GAS_BASE;
  case OPCODE_EXTCODESIZE:
  case OPCODE_EXTCODEHASH:
    return GAS_EXTERNAL;
  case OPCODE_EXTCODECOPY:
    return GAS_EXTERNAL;
  case OPCODE_RETURNDATASIZE:
    return GAS_BASE;
  case OPCODE_RETURNDATACOPY:
    return GAS_VERYLOW;
  case OPCODE_BLOCKHASH:
    return GAS_BLOCKHASH;
  case OPCODE_COINBASE:
  case OPCODE_TIMESTAMP:
  case OPCODE_NUMBER:
  case OPCODE_PREVRANDAO:
  case OPCODE_GASLIMIT:
  case OPCODE_CHAINID:
  case OPCODE_BASEFEE:
    return GAS_BASE;
  case OPCODE_SELFBALANCE:
    return GAS_LOW;
  case OPCODE_MLOAD:
  case OPCODE_MSTORE:
  case OPCODE_MSTORE8:
    return GAS_VERYLOW;
  case OPCODE_JUMP:
    return GAS_MID;
  case OPCODE_JUMPI:
    return GAS_HIGH;
  case OPCODE_PC:
    return GAS_BASE;
  case OPCODE_MSIZE:
    return GAS_BASE;
  case OPCODE_GAS:
    return GAS_BASE;
  case OPCODE_JUMPDEST:
    return GAS_JUMPDEST;
  case OPCODE_PUSH0:
    return GAS_BASE;
  case OPCODE_SLOAD:
    return 0;
  case OPCODE_SSTORE:
    return 0;
  case OPCODE_LOG0:
  case OPCODE_LOG1:
  case OPCODE_LOG2:
  case OPCODE_LOG3:
  case OPCODE_LOG4:
    return 0;
  case OPCODE_RETURN:
  case OPCODE_REVERT:
    return GAS_ZERO;
  case OPCODE_CREATE:
  case OPCODE_CREATE2:
    return GAS_CREATE;
  case OPCODE_CALL:
  case OPCODE_CALLCODE:
  case OPCODE_DELEGATECALL:
  case OPCODE_STATICCALL:
    return GAS_CALL;
  case OPCODE_SELFDESTRUCT:
    return GAS_SELFDESTRUCT;
  default:
    return 0;
  }
}

bool add_u64_overflow(uint64_t a, uint64_t b, uint64_t *out) {
  if (out == nullptr) {
    return true;
  }
#if NANO_EVM_HAVE_STDCKDINT
  return ckd_add(out, a, b);
#else
  if (a > UINT64_MAX - b) {
    return true;
  }
  *out = a + b;
  return false;
#endif
}

bool mul_u64_overflow(uint64_t a, uint64_t b, uint64_t *out) {
  if (out == nullptr) {
    return true;
  }
#if NANO_EVM_HAVE_STDCKDINT
  return ckd_mul(out, a, b);
#else
  if (a != 0 && b > UINT64_MAX / a) {
    return true;
  }
  *out = a * b;
  return false;
#endif
}

uint64_t memory_cost_words(size_t words) {
#if SIZE_MAX > UINT64_MAX
  if (words > UINT64_MAX) {
    return UINT64_MAX;
  }
#endif

  uint64_t w = (uint64_t)words;
  uint64_t linear = 0;
  if (mul_u64_overflow(w, 3U, &linear)) {
    return UINT64_MAX;
  }

  uint64_t q = w / 512U;
  uint64_t r = w % 512U;

  uint64_t quadratic = 0;
  if (mul_u64_overflow(w, q, &quadratic)) {
    return UINT64_MAX;
  }

  uint64_t q_mul_r = q * r;
  uint64_t r_mul_r_div = (r * r) / 512U;
  uint64_t tail = 0;
  if (add_u64_overflow(q_mul_r, r_mul_r_div, &tail)) {
    return UINT64_MAX;
  }
  if (add_u64_overflow(quadratic, tail, &quadratic)) {
    return UINT64_MAX;
  }

  uint64_t total = 0;
  if (add_u64_overflow(linear, quadratic, &total)) {
    return UINT64_MAX;
  }
  return total;
}

bool add_size_overflow(size_t a, size_t b, size_t *out) {
  if (out == nullptr) {
    return true;
  }
#if NANO_EVM_HAVE_STDCKDINT
  return ckd_add(out, a, b);
#else
  if (a > SIZE_MAX - b) {
    return true;
  }
  *out = a + b;
  return false;
#endif
}

bool mul_size_overflow(size_t a, size_t b, size_t *out) {
  if (out == nullptr) {
    return true;
  }
#if NANO_EVM_HAVE_STDCKDINT
  return ckd_mul(out, a, b);
#else
  if (a != 0U && b > (SIZE_MAX / a)) {
    return true;
  }
  *out = a * b;
  return false;
#endif
}

EVM_Status reserve_realloc_array(void **buffer, size_t *capacity,
                                 size_t min_capacity, size_t element_size) {
  if (buffer == nullptr || capacity == nullptr || element_size == 0U) {
    return EVM_ERR_INTERNAL;
  }
  if (min_capacity == 0U || *capacity >= min_capacity) {
    return EVM_OK;
  }

  size_t new_capacity = (*capacity == 0U) ? 8U : *capacity;
  while (new_capacity < min_capacity) {
    if (new_capacity > (SIZE_MAX / 2U)) {
      return EVM_ERR_RUNTIME;
    }
    new_capacity *= 2U;
  }

  size_t new_size = 0U;
  if (mul_size_overflow(new_capacity, element_size, &new_size)) {
    return EVM_ERR_RUNTIME;
  }

  void *new_buffer = realloc(*buffer, new_size);
  if (new_buffer == nullptr) {
    return EVM_ERR_OOM;
  }

  *buffer = new_buffer;
  *capacity = new_capacity;
  return EVM_OK;
}

static uint64_t hash_mix64(uint64_t value) {
  value ^= value >> 30U;
  value *= 0xbf58'476d'1ce4'e5b9U;
  value ^= value >> 27U;
  value *= 0x94d0'49bb'1331'11ebU;
  value ^= value >> 31U;
  return value;
}

size_t hash_uint256_value(const uint256_t *value) {
  uint64_t hash = 0x9e37'79b9'7f4a'7c15U;
  for (size_t i = 0; i < 4U; ++i) {
    hash ^= hash_mix64(value->limbs[i] + 0x9e37'79b9'7f4a'7c15U + (hash << 6U) +
                       (hash >> 2U));
  }
  return (size_t)hash;
}

size_t hash_access_entry(const uint256_t *address, const uint256_t *key) {
  uint64_t hash = 0x243f'6a88'85a3'08d3U;
  for (size_t i = 0; i < 4U; ++i) {
    hash ^= hash_mix64(address->limbs[i] + 0x9e37'79b9'7f4a'7c15U +
                       (hash << 6U) + (hash >> 2U));
  }
  for (size_t i = 0; i < 4U; ++i) {
    hash ^= hash_mix64(key->limbs[i] + 0x9e37'79b9'7f4a'7c15U + (hash << 6U) +
                       (hash >> 2U));
  }
  return (size_t)hash;
}

EVM_Status index_table_resize(size_t **table, size_t *capacity,
                              size_t entries_count) {
  if (table == nullptr || capacity == nullptr) {
    return EVM_ERR_INTERNAL;
  }

  if (entries_count == 0U) {
    free(*table);
    *table = nullptr;
    *capacity = 0U;
    return EVM_OK;
  }

  if (entries_count > (SIZE_MAX / 2U)) {
    return EVM_ERR_RUNTIME;
  }

  size_t required = entries_count * 2U;
  if (required < 8U) {
    required = 8U;
  }

  size_t target_capacity = 8U;
  while (target_capacity < required) {
    if (target_capacity > (SIZE_MAX / 2U)) {
      return EVM_ERR_RUNTIME;
    }
    target_capacity *= 2U;
  }

  size_t table_bytes = 0U;
  if (mul_size_overflow(target_capacity, sizeof(size_t), &table_bytes)) {
    return EVM_ERR_RUNTIME;
  }

  if (*table != nullptr && *capacity == target_capacity) {
    memset(*table, 0, table_bytes);
    return EVM_OK;
  }

  size_t *new_table = calloc(target_capacity, sizeof(size_t));
  if (new_table == nullptr) {
    return EVM_ERR_OOM;
  }
  free(*table);
  *table = new_table;
  *capacity = target_capacity;
  return EVM_OK;
}

static bool storage_index_lookup(const EVM_State *vm, const uint256_t *key,
                                 size_t *index_out) {
  if (vm->storage_index_table == nullptr ||
      vm->storage_index_table_capacity == 0U) {
    return false;
  }
  size_t mask = vm->storage_index_table_capacity - 1U;
  size_t slot = hash_uint256_value(key) & mask;
  for (size_t probe = 0U; probe < vm->storage_index_table_capacity; ++probe) {
    size_t entry = vm->storage_index_table[slot];
    if (entry == 0U) {
      return false;
    }
    size_t index = entry - 1U;
    if (index < vm->storage_count &&
        uint256_cmp(&vm->storage[index].key, key) == 0) {
      *index_out = index;
      return true;
    }
    slot = (slot + 1U) & mask;
  }
  return false;
}

EVM_Status storage_index_insert(EVM_State *vm, size_t index) {
  if (vm->storage_index_table == nullptr ||
      vm->storage_index_table_capacity == 0U || index >= vm->storage_count) {
    return EVM_ERR_INTERNAL;
  }
  size_t mask = vm->storage_index_table_capacity - 1U;
  const uint256_t *key = &vm->storage[index].key;
  size_t slot = hash_uint256_value(key) & mask;
  for (size_t probe = 0U; probe < vm->storage_index_table_capacity; ++probe) {
    size_t entry = vm->storage_index_table[slot];
    if (entry == 0U) {
      vm->storage_index_table[slot] = index + 1U;
      return EVM_OK;
    }
    size_t existing_index = entry - 1U;
    if (existing_index < vm->storage_count &&
        uint256_cmp(&vm->storage[existing_index].key, key) == 0) {
      vm->storage_index_table[slot] = index + 1U;
      return EVM_OK;
    }
    slot = (slot + 1U) & mask;
  }
  return EVM_ERR_INTERNAL;
}

EVM_Status storage_index_rebuild(EVM_State *vm) {
  if (vm->storage_count > 0U && vm->storage == nullptr) {
    return EVM_ERR_INTERNAL;
  }
  EVM_Status status =
      index_table_resize(&vm->storage_index_table,
                         &vm->storage_index_table_capacity, vm->storage_count);
  if (status != EVM_OK || vm->storage_count == 0U) {
    return status;
  }
  for (size_t i = 0; i < vm->storage_count; ++i) {
    status = storage_index_insert(vm, i);
    if (status != EVM_OK) {
      free(vm->storage_index_table);
      vm->storage_index_table = nullptr;
      vm->storage_index_table_capacity = 0U;
      return status;
    }
  }
  return EVM_OK;
}

bool storage_find(const EVM_State *vm, const uint256_t *key,
                  size_t *index_out) {
  if (vm->storage_count > 0U && vm->storage == nullptr) {
    return false;
  }
  if (storage_index_lookup(vm, key, index_out)) {
    return true;
  }
  for (size_t i = 0; i < vm->storage_count; ++i) {
    if (uint256_cmp(&vm->storage[i].key, key) == 0) {
      *index_out = i;
      return true;
    }
  }
  return false;
}
