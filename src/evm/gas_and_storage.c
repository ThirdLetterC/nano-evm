#include <stdlib.h>
#include <string.h>

#include "evm/gas_and_storage_internal.h"

static uint64_t uint256_to_u64_saturating(const uint256_t *value) {
  return uint256_fits_u64(value) ? value->limbs[0] : UINT64_MAX;
}

static EVM_Status size_to_words(size_t bytes, uint64_t *out_words) {
  if (bytes == 0) {
    *out_words = 0;
    return EVM_OK;
  }

  size_t padded = 0;
  if (add_size_overflow(bytes, 31U, &padded)) {
    return EVM_ERR_RUNTIME;
  }
  size_t words = padded / 32U;

#if SIZE_MAX > UINT64_MAX
  if (words > UINT64_MAX) {
    return EVM_ERR_RUNTIME;
  }
#endif
  *out_words = (uint64_t)words;
  return EVM_OK;
}

EVM_Status maybe_charge_sha3_word_gas(EVM_State *vm, size_t data_size) {
  uint64_t words = 0;
  EVM_Status status = size_to_words(data_size, &words);
  if (status != EVM_OK) {
    return status;
  }

  uint64_t words_cost = 0;
  if (mul_u64_overflow(words, GAS_SHA3_WORD, &words_cost)) {
    return out_of_gas(vm);
  }

  uint64_t total_cost = 0;
  if (add_u64_overflow(GAS_SHA3, words_cost, &total_cost)) {
    return out_of_gas(vm);
  }
  return charge_gas(vm, total_cost);
}

EVM_Status maybe_charge_copy_word_gas(EVM_State *vm, size_t data_size) {
  uint64_t words = 0;
  EVM_Status status = size_to_words(data_size, &words);
  if (status != EVM_OK) {
    return status;
  }

  uint64_t words_cost = 0;
  if (mul_u64_overflow(words, GAS_COPY_WORD, &words_cost)) {
    return out_of_gas(vm);
  }
  return charge_gas(vm, words_cost);
}

EVM_Status maybe_charge_create2_hash_gas(EVM_State *vm,
                                                size_t init_code_size) {
  uint64_t words = 0;
  EVM_Status status = size_to_words(init_code_size, &words);
  if (status != EVM_OK) {
    return status;
  }

  uint64_t words_cost = 0;
  if (mul_u64_overflow(words, GAS_SHA3_WORD, &words_cost)) {
    return out_of_gas(vm);
  }
  return charge_gas(vm, words_cost);
}

EVM_Status maybe_charge_initcode_word_gas(EVM_State *vm,
                                                 size_t init_code_size) {
  uint64_t words = 0;
  EVM_Status status = size_to_words(init_code_size, &words);
  if (status != EVM_OK) {
    return status;
  }

  uint64_t words_cost = 0;
  if (mul_u64_overflow(words, GAS_INITCODE_WORD, &words_cost)) {
    return out_of_gas(vm);
  }
  return charge_gas(vm, words_cost);
}

EVM_Status maybe_charge_account_access_gas(EVM_State *vm,
                                                  const uint256_t *address) {
  bool was_warm = false;
  EVM_Status status = warm_account_mark(vm, address, &was_warm);
  if (status != EVM_OK) {
    return status;
  }
  if (was_warm) {
    return EVM_OK;
  }
  return charge_gas(vm, GAS_ACCOUNT_ACCESS_COLD_SURCHARGE);
}

EVM_Status maybe_charge_selfdestruct_access_gas(EVM_State *vm,
                                                const uint256_t *address) {
  bool was_warm = false;
  EVM_Status status = warm_account_mark(vm, address, &was_warm);
  if (status != EVM_OK) {
    return status;
  }
  if (was_warm) {
    return EVM_OK;
  }
  return charge_gas(vm, GAS_ACCOUNT_ACCESS_COLD);
}

static bool account_is_non_empty_for_call(const EVM_State *vm,
                                          const uint256_t *address) {
  // Used for the CALL "new account with value" surcharge.
  if (address == nullptr) {
    return false;
  }

  if (uint256_cmp(address, &vm->address) == 0) {
    uint64_t nonce = 0U;
    EVM_RuntimeAccount account;
    if (runtime_account_read(vm, &vm->address, &account)) {
      nonce = account.nonce;
    }
    return nonce != 0U || !uint256_is_zero(&vm->self_balance) ||
           vm->code_size != 0U;
  }

  EVM_RuntimeAccount account;
  if (!runtime_account_read(vm, address, &account)) {
    return false;
  }

  return account.nonce != 0U || !uint256_is_zero(&account.balance) ||
         account.code_size != 0U;
}

EVM_Status charge_call_extra_gas(EVM_State *vm, bool has_value_transfer,
                                        const uint256_t *new_account_target) {
  uint64_t dynamic_call_cost = 0;
  if (has_value_transfer) {
    if (add_u64_overflow(dynamic_call_cost, GAS_CALL_VALUE_TRANSFER,
                         &dynamic_call_cost)) {
      return out_of_gas(vm);
    }

    if (new_account_target != nullptr &&
        !account_is_non_empty_for_call(vm, new_account_target)) {
      if (add_u64_overflow(dynamic_call_cost, GAS_CALL_NEW_ACCOUNT,
                           &dynamic_call_cost)) {
        return out_of_gas(vm);
      }
    }
  }

  return charge_gas(vm, dynamic_call_cost);
}

EVM_Status charge_call_forwarded_gas(EVM_State *vm,
                                            const uint256_t *requested_gas,
                                            bool has_value_transfer,
                                            uint64_t *out_forwarded_gas) {
  EVM_Status status = EVM_OK;
  // EIP-150: child execution gets at most all-but-one-64th of caller gas.
  uint64_t capped_by_eip150 = vm->gas_remaining - (vm->gas_remaining / 64U);
  uint64_t caller_forwarded = uint256_to_u64_saturating(requested_gas);
  if (caller_forwarded > capped_by_eip150) {
    caller_forwarded = capped_by_eip150;
  }

  uint64_t child_forwarded = caller_forwarded;
  uint64_t caller_charge = caller_forwarded;
  if (has_value_transfer) {
    // Value-bearing calls grant callee stipend gas and charge it upfront.
    if (add_u64_overflow(child_forwarded, GAS_CALL_STIPEND, &child_forwarded) ||
        add_u64_overflow(caller_charge, GAS_CALL_STIPEND, &caller_charge)) {
      return out_of_gas(vm);
    }
  }

  status = charge_gas(vm, caller_charge);
  if (status != EVM_OK) {
    return status;
  }
  *out_forwarded_gas = child_forwarded;
  return EVM_OK;
}

EVM_Status charge_create_forwarded_gas(EVM_State *vm,
                                              uint64_t *out_forwarded_gas) {
  uint64_t capped_by_eip150 = vm->gas_remaining - (vm->gas_remaining / 64U);
  EVM_Status status = charge_gas(vm, capped_by_eip150);
  if (status != EVM_OK) {
    return status;
  }
  *out_forwarded_gas = capped_by_eip150;
  return EVM_OK;
}

EVM_Status
maybe_charge_code_deposit_gas(EVM_State *vm, size_t code_size) {
  if (code_size > MAX_CODE_SIZE) {
    return out_of_gas(vm);
  }

#if SIZE_MAX > UINT64_MAX
  if (code_size > UINT64_MAX) {
    return out_of_gas(vm);
  }
#endif

  uint64_t cost = 0;
  if (mul_u64_overflow((uint64_t)code_size, GAS_CODE_DEPOSIT, &cost)) {
    return out_of_gas(vm);
  }
  return charge_gas(vm, cost);
}

EVM_Status copy_to_memory(EVM_State *vm, size_t memory_offset,
                                 size_t data_offset, size_t data_size,
                                 const uint8_t *source, size_t source_size,
                                 bool strict_bounds) {
  size_t data_end = 0;
  if (add_size_overflow(data_offset, data_size, &data_end)) {
    if (strict_bounds) {
      return invalid_opcode(vm);
    }
    return EVM_ERR_RUNTIME;
  }

  if (strict_bounds && data_end > source_size) {
    return invalid_opcode(vm);
  }

  if (data_size == 0U) {
    return EVM_OK;
  }

  size_t memory_end = 0;
  if (add_size_overflow(memory_offset, data_size, &memory_end)) {
    return EVM_ERR_RUNTIME;
  }
  EVM_Status status = evm_memory_ensure(vm, memory_end);
  if (status != EVM_OK) {
    return status;
  }

  memset(vm->memory + memory_offset, 0, data_size);

  if (data_offset >= source_size) {
    return EVM_OK;
  }

  size_t copy_size = source_size - data_offset;
  if (copy_size > data_size) {
    copy_size = data_size;
  }
  if (copy_size == 0U) {
    return EVM_OK;
  }
  if (source == nullptr) {
    return EVM_ERR_INTERNAL;
  }

  memcpy(vm->memory + memory_offset, source + data_offset, copy_size);
  return EVM_OK;
}

EVM_Status maybe_charge_exp_byte_gas(EVM_State *vm,
                                            const uint256_t *exponent) {
  uint64_t exponent_bytes = uint256_significant_bytes(exponent);
  uint64_t additional_cost = 0;
  if (mul_u64_overflow(exponent_bytes, GAS_EXP_BYTE, &additional_cost)) {
    return out_of_gas(vm);
  }
  return charge_gas(vm, additional_cost);
}

EVM_Status maybe_apply_refund(EVM_State *vm) {
  // Refund settles only once per transaction and is capped at one-fifth used.
  if (vm->call_depth != 0U) {
    return EVM_OK;
  }

  if (vm->refund_counter > 0) {
    uint64_t gas_used = vm->gas_limit - vm->gas_remaining;
    uint64_t max_refund = gas_used / 5U;
    uint64_t refund = (uint64_t)vm->refund_counter;
    if (refund > max_refund) {
      refund = max_refund;
    }

    if (add_u64_overflow(vm->gas_remaining, refund, &vm->gas_remaining)) {
      return EVM_ERR_INTERNAL;
    }
  }
  return runtime_accounts_apply_selfdestructs(vm);
}

static void refund_counter_add(EVM_State *vm, int64_t delta) {
  if (delta > 0 && vm->refund_counter > (INT64_MAX - delta)) {
    vm->refund_counter = INT64_MAX;
    return;
  }
  if (delta < 0 && vm->refund_counter < (INT64_MIN - delta)) {
    vm->refund_counter = INT64_MIN;
    return;
  }
  vm->refund_counter += delta;
}

EVM_Status sstore_berlin(EVM_State *vm, const uint256_t *key,
                                const uint256_t *next) {
  size_t index = 0;
  bool exists = storage_find(vm, key, &index);

  // SSTORE gas/refund depends on current value and both frame/tx snapshots.
  uint256_t current = exists ? vm->storage[index].value : uint256_zero();
  uint256_t original = exists ? vm->storage[index].original : uint256_zero();
  uint256_t tx_original =
      exists ? vm->storage[index].tx_original : uint256_zero();
  bool existed_at_transaction_start =
      exists ? vm->storage[index].existed_at_transaction_start : false;

  bool was_warm = false;
  EVM_Status status = warm_slot_mark(vm, &vm->address, key, &was_warm);
  if (status != EVM_OK) {
    return status;
  }

  uint64_t gas_cost = was_warm ? 0 : GAS_SLOAD_COLD;
  int64_t refund_delta = 0;

  if (uint256_cmp(&current, next) == 0) {
    if (add_u64_overflow(gas_cost, GAS_SLOAD_WARM, &gas_cost)) {
      return out_of_gas(vm);
    }
  } else if (uint256_cmp(&tx_original, &current) == 0) {
    if (uint256_is_zero(&tx_original)) {
      if (add_u64_overflow(gas_cost, GAS_SSTORE_SET, &gas_cost)) {
        return out_of_gas(vm);
      }
    } else {
      if (add_u64_overflow(gas_cost, GAS_SSTORE_RESET, &gas_cost)) {
        return out_of_gas(vm);
      }
      if (uint256_is_zero(next)) {
        refund_delta += (int64_t)GAS_SSTORE_CLEARS_SCHEDULE;
      }
    }
  } else {
    // Dirty slot rewrite: warm touch cost plus refund corrections.
    if (add_u64_overflow(gas_cost, GAS_SLOAD_WARM, &gas_cost)) {
      return out_of_gas(vm);
    }
    if (!uint256_is_zero(&tx_original)) {
      if (uint256_is_zero(&current)) {
        refund_delta -= (int64_t)GAS_SSTORE_CLEARS_SCHEDULE;
      }
      if (uint256_is_zero(next)) {
        refund_delta += (int64_t)GAS_SSTORE_CLEARS_SCHEDULE;
      }
    }
    if (uint256_cmp(&tx_original, next) == 0) {
      if (uint256_is_zero(&tx_original)) {
        refund_delta += (int64_t)(GAS_SSTORE_SET - GAS_SLOAD_WARM);
      } else {
        refund_delta += (int64_t)(GAS_SSTORE_RESET - GAS_SLOAD_WARM);
      }
    }
  }

  status = charge_gas(vm, gas_cost);
  if (status != EVM_OK) {
    return status;
  }

  refund_counter_add(vm, refund_delta);

  if (exists) {
    vm->storage[index].value = *next;
    return EVM_OK;
  }

  return storage_set(vm, key, next, &original, false, &tx_original,
                     existed_at_transaction_start);
}
EVM_Status append_log(EVM_State *vm, const uint256_t topics[4],
                             size_t topics_count, const uint8_t *data,
                             size_t data_size) {
  if (vm->logs_count == vm->logs_capacity) {
    EVM_Status status =
        reserve_realloc_array((void **)&vm->logs, &vm->logs_capacity,
                              vm->logs_count + 1U, sizeof(EVM_LogEntry));
    if (status != EVM_OK) {
      return status;
    }
  }

  EVM_LogEntry entry;
  memset(&entry, 0, sizeof(entry));
  entry.topics_count = topics_count;
  for (size_t i = 0; i < topics_count; ++i) {
    entry.topics[i] = topics[i];
  }

  if (data_size > 0) {
    entry.data = calloc(data_size, sizeof(uint8_t));
    if (entry.data == nullptr) {
      return EVM_ERR_OOM;
    }
    memcpy(entry.data, data, data_size);
    entry.data_size = data_size;
  }

  vm->logs[vm->logs_count++] = entry;
  return EVM_OK;
}
