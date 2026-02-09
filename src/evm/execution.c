#include <stdlib.h>
#include <string.h>

#include "evm/call_and_create_internal.h"
#include "keccak.h"

static EVM_Status stack_require(const EVM_State *vm, size_t depth) {
  return (stack_depth(&vm->stack) >= depth) ? EVM_OK : EVM_ERR_STACK_UNDERFLOW;
}

static EVM_Status pop_uint256(EVM_State *vm, uint256_t *out) {
  return (stack_pop(&vm->stack, out) == STACK_OK) ? EVM_OK
                                                  : EVM_ERR_STACK_UNDERFLOW;
}

static EVM_Status push_uint256(EVM_State *vm, const uint256_t *value) {
  return (stack_push(&vm->stack, value) == STACK_OK) ? EVM_OK
                                                     : EVM_ERR_STACK_OVERFLOW;
}

static EVM_Status pop_size_t(EVM_State *vm, size_t *out) {
  uint256_t value = uint256_zero();
  EVM_Status status = pop_uint256(vm, &value);
  if (status != EVM_OK) {
    return status;
  }
  if (!uint256_fits_size_t(&value)) {
    return EVM_ERR_RUNTIME;
  }
  *out = uint256_to_size_t(&value);
  return EVM_OK;
}

static uint256_t normalize_address_word(const uint256_t *word) {
  // EVM addresses are the low 160 bits of stack words.
  uint256_t address = *word;
  address.limbs[2] &= 0xffff'ffffU;
  address.limbs[3] = 0U;
  return address;
}

static void jumpdest_bitmap_set(uint8_t *bitmap, size_t offset) {
  bitmap[offset / 8U] |= (uint8_t)(1U << (offset % 8U));
}

static bool jumpdest_bitmap_get(const uint8_t *bitmap, size_t bitmap_size,
                                size_t offset) {
  size_t byte_index = offset / 8U;
  if (byte_index >= bitmap_size) {
    return false;
  }
  return (bitmap[byte_index] & (uint8_t)(1U << (offset % 8U))) != 0U;
}

static EVM_Status build_jumpdest_bitmap(EVM_State *vm) {
  vm->jumpdest_bitmap = nullptr;
  vm->jumpdest_bitmap_size = 0;
  if (vm->code_size == 0U) {
    return EVM_OK;
  }

  size_t padded_bits = 0U;
  if (add_size_overflow(vm->code_size, 7U, &padded_bits)) {
    return EVM_ERR_RUNTIME;
  }
  size_t bitmap_size = padded_bits / 8U;
  if (bitmap_size == 0U) {
    return EVM_ERR_RUNTIME;
  }

  uint8_t *bitmap = calloc(bitmap_size, sizeof(uint8_t));
  if (bitmap == nullptr) {
    return EVM_ERR_OOM;
  }

  // JUMP/JUMPI may only target explicit JUMPDEST opcodes, never PUSH payload.
  size_t pc = 0U;
  while (pc < vm->code_size) {
    uint8_t opcode = vm->code[pc];
    if (opcode == OPCODE_JUMPDEST) {
      jumpdest_bitmap_set(bitmap, pc);
    }

    pc += 1U;
    if (opcode >= OPCODE_PUSH1 && opcode <= OPCODE_PUSH32) {
      size_t push_len = (size_t)(opcode - OPCODE_PUSH1) + 1U;
      if (vm->code_size - pc < push_len) {
        break;
      }
      pc += push_len;
    }
  }

  vm->jumpdest_bitmap = bitmap;
  vm->jumpdest_bitmap_size = bitmap_size;
  return EVM_OK;
}

static bool is_valid_jumpdest(const EVM_State *vm, size_t destination) {
  if (destination >= vm->code_size) {
    return false;
  }
  if (vm->jumpdest_bitmap == nullptr || vm->jumpdest_bitmap_size == 0U) {
    return false;
  }
  return jumpdest_bitmap_get(vm->jumpdest_bitmap, vm->jumpdest_bitmap_size,
                             destination);
}

static void runtime_accounts_destroy(EVM_State *vm) {
  runtime_accounts_release(vm);
}

EVM_Status evm_init(EVM_State *vm, const uint8_t *code, size_t code_size,
                    uint64_t gas_limit) {
  if (vm == nullptr) {
    return EVM_ERR_INVALID_BYTECODE;
  }
  if (code == nullptr && code_size != 0) {
    return EVM_ERR_INVALID_BYTECODE;
  }

  vm->pc = 0;
  vm->gas_limit = gas_limit;
  vm->gas_remaining = gas_limit;
  vm->refund_counter = 0;
  stack_init(&vm->stack);
  vm->memory = nullptr;
  vm->memory_size = 0;
  vm->call_data = nullptr;
  vm->call_data_size = 0;
  vm->return_data = nullptr;
  vm->return_data_size = 0;
  vm->storage = nullptr;
  vm->storage_count = 0;
  vm->storage_capacity = 0;
  vm->storage_index_table = nullptr;
  vm->storage_index_table_capacity = 0;
  vm->transient_storage = nullptr;
  vm->transient_storage_count = 0;
  vm->transient_storage_capacity = 0;
  vm->warm_accounts = nullptr;
  vm->warm_accounts_count = 0;
  vm->warm_accounts_capacity = 0;
  vm->warm_accounts_index_table = nullptr;
  vm->warm_accounts_index_table_capacity = 0;
  vm->warm_slots = nullptr;
  vm->warm_slots_count = 0;
  vm->warm_slots_capacity = 0;
  vm->warm_slots_index_table = nullptr;
  vm->warm_slots_index_table_capacity = 0;
  vm->logs = nullptr;
  vm->logs_count = 0;
  vm->logs_capacity = 0;
  vm->address = uint256_zero();
  vm->self_balance = uint256_zero();
  vm->origin = uint256_zero();
  vm->caller = uint256_zero();
  vm->call_value = uint256_zero();
  vm->call_depth = 0;
  vm->gas_price = uint256_zero();
  vm->coinbase = uint256_zero();
  vm->timestamp = uint256_zero();
  vm->block_number = uint256_zero();
  vm->prev_randao = uint256_zero();
  vm->block_gas_limit = uint256_zero();
  vm->chain_id = uint256_zero();
  vm->base_fee = uint256_zero();
  vm->blob_base_fee = uint256_zero();
  vm->blob_hashes = nullptr;
  vm->blob_hashes_count = 0;
  vm->external_accounts = nullptr;
  vm->external_accounts_count = 0;
  vm->block_hashes = nullptr;
  vm->block_hashes_count = 0;
  vm->runtime_accounts = nullptr;
  vm->runtime_accounts_count = 0;
  vm->runtime_accounts_capacity = 0;
  vm->is_static_context = false;
  vm->code = code;
  vm->code_size = code_size;
  vm->jumpdest_bitmap = nullptr;
  vm->jumpdest_bitmap_size = 0;
  return build_jumpdest_bitmap(vm);
}

void evm_destroy(EVM_State *vm) {
  if (vm == nullptr) {
    return;
  }
  free(vm->memory);
  vm->memory = nullptr;
  vm->memory_size = 0;
  vm->call_data = nullptr;
  vm->call_data_size = 0;

  clear_return_data(vm);

  free(vm->storage);
  vm->storage = nullptr;
  vm->storage_count = 0;
  vm->storage_capacity = 0;
  free(vm->storage_index_table);
  vm->storage_index_table = nullptr;
  vm->storage_index_table_capacity = 0;

  free(vm->transient_storage);
  vm->transient_storage = nullptr;
  vm->transient_storage_count = 0;
  vm->transient_storage_capacity = 0;

  free(vm->warm_accounts);
  vm->warm_accounts = nullptr;
  vm->warm_accounts_count = 0;
  vm->warm_accounts_capacity = 0;
  free(vm->warm_accounts_index_table);
  vm->warm_accounts_index_table = nullptr;
  vm->warm_accounts_index_table_capacity = 0;

  free(vm->warm_slots);
  vm->warm_slots = nullptr;
  vm->warm_slots_count = 0;
  vm->warm_slots_capacity = 0;
  free(vm->warm_slots_index_table);
  vm->warm_slots_index_table = nullptr;
  vm->warm_slots_index_table_capacity = 0;

  for (size_t i = 0; i < vm->logs_count; ++i) {
    free(vm->logs[i].data);
  }
  free(vm->logs);
  vm->logs = nullptr;
  vm->logs_count = 0;
  vm->logs_capacity = 0;

  vm->blob_hashes = nullptr;
  vm->blob_hashes_count = 0;
  vm->external_accounts = nullptr;
  vm->external_accounts_count = 0;
  vm->block_hashes = nullptr;
  vm->block_hashes_count = 0;
  free(vm->jumpdest_bitmap);
  vm->jumpdest_bitmap = nullptr;
  vm->jumpdest_bitmap_size = 0;

  runtime_accounts_destroy(vm);
  vm->is_static_context = false;
}

EVM_Status evm_memory_ensure(EVM_State *vm, size_t required_size) {
  if (required_size <= vm->memory_size) {
    return EVM_OK;
  }

  size_t old_padded = 0;
  if (add_size_overflow(vm->memory_size, 31U, &old_padded)) {
    return EVM_ERR_RUNTIME;
  }
  size_t old_words = old_padded / 32U;

  size_t new_padded = 0;
  if (add_size_overflow(required_size, 31U, &new_padded)) {
    return EVM_ERR_RUNTIME;
  }
  size_t new_words = new_padded / 32U;
  if (new_words > (SIZE_MAX / 32U)) {
    return EVM_ERR_RUNTIME;
  }
  size_t new_size = new_words * 32U;
  if (new_size < required_size) {
    return EVM_ERR_RUNTIME;
  }

  // Charge only the delta of the Yellow Paper memory-cost curve.
  uint64_t old_cost = memory_cost_words(old_words);
  uint64_t new_cost = memory_cost_words(new_words);
  if (new_cost < old_cost) {
    return EVM_ERR_RUNTIME;
  }
  uint64_t additional_cost = new_cost - old_cost;

  if (vm->gas_remaining < additional_cost) {
    return out_of_gas(vm);
  }

  uint8_t *new_memory = realloc(vm->memory, new_size);
  if (new_memory == nullptr) {
    return EVM_ERR_OOM;
  }

  if (new_size > vm->memory_size) {
    memset(new_memory + vm->memory_size, 0, new_size - vm->memory_size);
  }

  vm->memory = new_memory;
  vm->memory_size = new_size;
  vm->gas_remaining -= additional_cost;
  return EVM_OK;
}

EVM_Status evm_execute(EVM_State *vm) {
  size_t tx_access_account_count = 0U;
  size_t tx_access_slot_count = 0U;
  EVM_Status status = EVM_OK;
  // Top-level entry starts a new transaction scope for warm sets, refunds, and
  // transient state.
  if (vm->call_depth == 0U) {
    tx_access_account_count = vm->warm_accounts_count;
    tx_access_slot_count = vm->warm_slots_count;
    if ((tx_access_account_count > 0U && vm->warm_accounts == nullptr) ||
        (tx_access_slot_count > 0U && vm->warm_slots == nullptr)) {
      return EVM_ERR_INTERNAL;
    }
    vm->warm_accounts_count = 0;
    vm->warm_slots_count = 0;
    status = index_table_resize(&vm->warm_accounts_index_table,
                                &vm->warm_accounts_index_table_capacity, 0U);
    if (status != EVM_OK) {
      return status;
    }
    status = index_table_resize(&vm->warm_slots_index_table,
                                &vm->warm_slots_index_table_capacity, 0U);
    if (status != EVM_OK) {
      return status;
    }
    vm->transient_storage_count = 0;
    for (size_t i = 0; i < vm->runtime_accounts_count; ++i) {
      vm->runtime_accounts[i].transient_storage_count = 0;
    }
    rollback_logs(vm, 0U);
    vm->refund_counter = 0;
    storage_snapshot_transaction_originals(vm);
    runtime_accounts_snapshot_transaction_originals(vm);
  }
  clear_return_data(vm);
  // Per-frame snapshots support REVERT without discarding parent-frame changes.
  const int64_t refund_start = vm->refund_counter;
  storage_snapshot_originals(vm);
  size_t logs_start_count = vm->logs_count;

  bool was_warm = false;
  if (vm->call_depth == 0U) {
    for (size_t i = 0; i < tx_access_account_count; ++i) {
      uint256_t access_address = vm->warm_accounts[i];
      status = warm_account_mark(vm, &access_address, &was_warm);
      if (status != EVM_OK) {
        return status;
      }
    }

    for (size_t i = 0; i < tx_access_slot_count; ++i) {
      EVM_AccessEntry access_entry = vm->warm_slots[i];
      status = warm_account_mark(vm, &access_entry.address, &was_warm);
      if (status != EVM_OK) {
        return status;
      }
      status = warm_slot_mark(vm, &access_entry.address, &access_entry.key,
                              &was_warm);
      if (status != EVM_OK) {
        return status;
      }
    }

    for (uint64_t precompile_id = 1U; precompile_id <= 9U; ++precompile_id) {
      uint256_t precompile_address = uint256_from_u64(precompile_id);
      status = warm_account_mark(vm, &precompile_address, &was_warm);
      if (status != EVM_OK) {
        return status;
      }
    }
  }

  status = warm_account_mark(vm, &vm->address, &was_warm);
  if (status != EVM_OK) {
    return status;
  }
  status = warm_account_mark(vm, &vm->caller, &was_warm);
  if (status != EVM_OK) {
    return status;
  }
  status = warm_account_mark(vm, &vm->coinbase, &was_warm);
  if (status != EVM_OK) {
    return status;
  }

  while (vm->pc < vm->code_size) {
    uint8_t opcode = vm->code[vm->pc++];
    uint64_t gas_cost = opcode_base_gas_cost(opcode);
    status = charge_gas(vm, gas_cost);

    if (status != EVM_OK) {
      return status;
    }

    if (opcode == OPCODE_PUSH0) {
      uint256_t value = uint256_zero();
      status = push_uint256(vm, &value);
      if (status != EVM_OK) {
        return status;
      }
      continue;
    }

    if (opcode >= OPCODE_PUSH1 && opcode <= OPCODE_PUSH32) {
      size_t push_len = (size_t)(opcode - OPCODE_PUSH1) + 1U;
      if (vm->pc + push_len > vm->code_size) {
        return EVM_ERR_INVALID_BYTECODE;
      }

      uint8_t be_word[32] = {0};
      memcpy(be_word + (32U - push_len), vm->code + vm->pc, push_len);
      vm->pc += push_len;

      uint256_t value = uint256_zero();
      uint256_from_be_bytes(&value, be_word);

      status = push_uint256(vm, &value);
      if (status != EVM_OK) {
        return status;
      }
      continue;
    }

    if (opcode >= OPCODE_DUP1 && opcode <= OPCODE_DUP16) {
      size_t depth = (size_t)(opcode - OPCODE_DUP1) + 1U;
      status = stack_require(vm, depth);
      if (status != EVM_OK) {
        return status;
      }

      uint256_t value = vm->stack.data[vm->stack.top - depth];
      status = push_uint256(vm, &value);
      if (status != EVM_OK) {
        return status;
      }
      continue;
    }

    if (opcode >= OPCODE_SWAP1 && opcode <= OPCODE_SWAP16) {
      size_t depth = (size_t)(opcode - OPCODE_SWAP1) + 1U;
      status = stack_require(vm, depth + 1U);
      if (status != EVM_OK) {
        return status;
      }

      size_t top_index = vm->stack.top - 1U;
      size_t swap_index = top_index - depth;
      uint256_t top = vm->stack.data[top_index];
      vm->stack.data[top_index] = vm->stack.data[swap_index];
      vm->stack.data[swap_index] = top;
      continue;
    }

    switch (opcode) {
    case OPCODE_STOP:
      return maybe_apply_refund(vm);
    case OPCODE_POP: {
      uint256_t ignored = uint256_zero();
      status = pop_uint256(vm, &ignored);
      if (status != EVM_OK) {
        return status;
      }
      break;
    }
    case OPCODE_ADD:
    case OPCODE_SUB:
    case OPCODE_MUL:
    case OPCODE_DIV:
    case OPCODE_SDIV:
    case OPCODE_MOD:
    case OPCODE_SMOD:
    case OPCODE_LT:
    case OPCODE_GT:
    case OPCODE_SLT:
    case OPCODE_SGT:
    case OPCODE_EQ:
    case OPCODE_AND:
    case OPCODE_OR:
    case OPCODE_XOR:
    case OPCODE_BYTE:
    case OPCODE_SHL:
    case OPCODE_SHR:
    case OPCODE_SAR: {
      status = stack_require(vm, 2U);
      if (status != EVM_OK) {
        return status;
      }

      uint256_t a = uint256_zero();
      uint256_t b = uint256_zero();
      // EVM pops the right operand first, so arithmetic is b (op) a.
      (void)pop_uint256(vm, &a);
      (void)pop_uint256(vm, &b);

      uint256_t result = uint256_zero();
      if (opcode == OPCODE_ADD) {
        result = uint256_add(&b, &a);
      } else if (opcode == OPCODE_SUB) {
        result = uint256_sub(&b, &a);
      } else if (opcode == OPCODE_MUL) {
        result = uint256_mul(&b, &a);
      } else if (opcode == OPCODE_DIV) {
        result = uint256_div(&b, &a);
      } else if (opcode == OPCODE_SDIV) {
        result = uint256_sdiv(&b, &a);
      } else if (opcode == OPCODE_MOD) {
        result = uint256_mod(&b, &a);
      } else if (opcode == OPCODE_SMOD) {
        result = uint256_smod(&b, &a);
      } else if (opcode == OPCODE_LT) {
        result = uint256_from_u64((uint256_cmp(&b, &a) < 0) ? 1U : 0U);
      } else if (opcode == OPCODE_GT) {
        result = uint256_from_u64((uint256_cmp(&b, &a) > 0) ? 1U : 0U);
      } else if (opcode == OPCODE_SLT) {
        result = uint256_from_u64((uint256_scmp(&b, &a) < 0) ? 1U : 0U);
      } else if (opcode == OPCODE_SGT) {
        result = uint256_from_u64((uint256_scmp(&b, &a) > 0) ? 1U : 0U);
      } else if (opcode == OPCODE_EQ) {
        result = uint256_from_u64((uint256_cmp(&b, &a) == 0) ? 1U : 0U);
      } else if (opcode == OPCODE_AND) {
        result = uint256_and(&b, &a);
      } else if (opcode == OPCODE_OR) {
        result = uint256_or(&b, &a);
      } else if (opcode == OPCODE_XOR) {
        result = uint256_xor(&b, &a);
      } else if (opcode == OPCODE_BYTE) {
        result = uint256_byte(&b, &a);
      } else if (opcode == OPCODE_SHL) {
        result = uint256_shl(&b, &a);
      } else if (opcode == OPCODE_SHR) {
        result = uint256_shr(&b, &a);
      } else if (opcode == OPCODE_SAR) {
        result = uint256_sar(&b, &a);
      }

      status = push_uint256(vm, &result);
      if (status != EVM_OK) {
        return status;
      }
      break;
    }
    case OPCODE_ISZERO:
    case OPCODE_NOT: {
      status = stack_require(vm, 1U);
      if (status != EVM_OK) {
        return status;
      }

      uint256_t value = uint256_zero();
      (void)pop_uint256(vm, &value);

      uint256_t result = uint256_zero();
      if (opcode == OPCODE_ISZERO) {
        result = uint256_from_u64(uint256_is_zero(&value) ? 1U : 0U);
      } else {
        result = uint256_not(&value);
      }

      status = push_uint256(vm, &result);
      if (status != EVM_OK) {
        return status;
      }
      break;
    }
    case OPCODE_ADDMOD:
    case OPCODE_MULMOD: {
      status = stack_require(vm, 3U);
      if (status != EVM_OK) {
        return status;
      }

      uint256_t a = uint256_zero();
      uint256_t b = uint256_zero();
      uint256_t c = uint256_zero();
      (void)pop_uint256(vm, &a);
      (void)pop_uint256(vm, &b);
      (void)pop_uint256(vm, &c);

      uint256_t result = uint256_zero();
      if (opcode == OPCODE_ADDMOD) {
        result = uint256_addmod(&c, &b, &a);
      } else {
        result = uint256_mulmod(&c, &b, &a);
      }

      status = push_uint256(vm, &result);
      if (status != EVM_OK) {
        return status;
      }
      break;
    }
    case OPCODE_EXP:
    case OPCODE_SIGNEXTEND: {
      status = stack_require(vm, 2U);
      if (status != EVM_OK) {
        return status;
      }

      uint256_t a = uint256_zero();
      uint256_t b = uint256_zero();
      (void)pop_uint256(vm, &a);
      (void)pop_uint256(vm, &b);

      uint256_t result = uint256_zero();
      if (opcode == OPCODE_EXP) {
        status = maybe_charge_exp_byte_gas(vm, &a);
        if (status != EVM_OK) {
          return status;
        }
        result = uint256_exp(&b, &a);
      } else {
        result = uint256_signextend(&b, &a);
      }

      status = push_uint256(vm, &result);
      if (status != EVM_OK) {
        return status;
      }
      break;
    }
    case OPCODE_JUMP: {
      size_t destination = 0;
      status = pop_size_t(vm, &destination);
      if (status != EVM_OK) {
        return status;
      }
      if (!is_valid_jumpdest(vm, destination)) {
        return invalid_opcode(vm);
      }
      vm->pc = destination;
      break;
    }
    case OPCODE_JUMPI: {
      size_t destination = 0;
      uint256_t condition = uint256_zero();

      status = stack_require(vm, 2U);
      if (status != EVM_OK) {
        return status;
      }
      status = pop_size_t(vm, &destination);
      if (status != EVM_OK) {
        return status;
      }
      status = pop_uint256(vm, &condition);
      if (status != EVM_OK) {
        return status;
      }

      if (!uint256_is_zero(&condition)) {
        if (!is_valid_jumpdest(vm, destination)) {
          return invalid_opcode(vm);
        }
        vm->pc = destination;
      }
      break;
    }
    case OPCODE_PC: {
      size_t pc_value = vm->pc - 1U;
#if SIZE_MAX > UINT64_MAX
      if (pc_value > UINT64_MAX) {
        return EVM_ERR_RUNTIME;
      }
#endif
      uint256_t value = uint256_from_u64((uint64_t)pc_value);
      status = push_uint256(vm, &value);
      if (status != EVM_OK) {
        return status;
      }
      break;
    }
    case OPCODE_ADDRESS:
      status = push_uint256(vm, &vm->address);
      if (status != EVM_OK) {
        return status;
      }
      break;
    case OPCODE_BALANCE: {
      uint256_t account_address = uint256_zero();
      status = stack_require(vm, 1U);
      if (status != EVM_OK) {
        return status;
      }
      status = pop_uint256(vm, &account_address);
      if (status != EVM_OK) {
        return status;
      }
      account_address = normalize_address_word(&account_address);
      status = maybe_charge_account_access_gas(vm, &account_address);
      if (status != EVM_OK) {
        return status;
      }
      uint256_t value = account_balance_get(vm, &account_address);
      status = push_uint256(vm, &value);
      if (status != EVM_OK) {
        return status;
      }
      break;
    }
    case OPCODE_ORIGIN:
      status = push_uint256(vm, &vm->origin);
      if (status != EVM_OK) {
        return status;
      }
      break;
    case OPCODE_CALLER:
      status = push_uint256(vm, &vm->caller);
      if (status != EVM_OK) {
        return status;
      }
      break;
    case OPCODE_CALLVALUE:
      status = push_uint256(vm, &vm->call_value);
      if (status != EVM_OK) {
        return status;
      }
      break;
    case OPCODE_CALLDATALOAD: {
      size_t data_offset = 0;
      status = stack_require(vm, 1U);
      if (status != EVM_OK) {
        return status;
      }
      status = pop_size_t(vm, &data_offset);
      if (status != EVM_OK) {
        return status;
      }

      uint8_t word[32] = {0};
      if (vm->call_data != nullptr && data_offset < vm->call_data_size) {
        size_t copy_size = vm->call_data_size - data_offset;
        if (copy_size > 32U) {
          copy_size = 32U;
        }
        memcpy(word, vm->call_data + data_offset, copy_size);
      }

      uint256_t value = uint256_zero();
      uint256_from_be_bytes(&value, word);
      status = push_uint256(vm, &value);
      if (status != EVM_OK) {
        return status;
      }
      break;
    }
    case OPCODE_CALLDATASIZE: {
#if SIZE_MAX > UINT64_MAX
      if (vm->call_data_size > UINT64_MAX) {
        return EVM_ERR_RUNTIME;
      }
#endif
      uint256_t value = uint256_from_u64((uint64_t)vm->call_data_size);
      status = push_uint256(vm, &value);
      if (status != EVM_OK) {
        return status;
      }
      break;
    }
    case OPCODE_CALLDATACOPY: {
      size_t memory_offset = 0;
      size_t data_offset = 0;
      size_t data_size = 0;
      status = stack_require(vm, 3U);
      if (status != EVM_OK) {
        return status;
      }
      status = pop_size_t(vm, &memory_offset);
      if (status != EVM_OK) {
        return status;
      }
      status = pop_size_t(vm, &data_offset);
      if (status != EVM_OK) {
        return status;
      }
      status = pop_size_t(vm, &data_size);
      if (status != EVM_OK) {
        return status;
      }
      status = maybe_charge_copy_word_gas(vm, data_size);
      if (status != EVM_OK) {
        return status;
      }
      status = copy_to_memory(vm, memory_offset, data_offset, data_size,
                              vm->call_data, vm->call_data_size, false);
      if (status != EVM_OK) {
        return status;
      }
      break;
    }
    case OPCODE_CODESIZE: {
#if SIZE_MAX > UINT64_MAX
      if (vm->code_size > UINT64_MAX) {
        return EVM_ERR_RUNTIME;
      }
#endif
      uint256_t value = uint256_from_u64((uint64_t)vm->code_size);
      status = push_uint256(vm, &value);
      if (status != EVM_OK) {
        return status;
      }
      break;
    }
    case OPCODE_CODECOPY: {
      size_t memory_offset = 0;
      size_t data_offset = 0;
      size_t data_size = 0;
      status = stack_require(vm, 3U);
      if (status != EVM_OK) {
        return status;
      }
      status = pop_size_t(vm, &memory_offset);
      if (status != EVM_OK) {
        return status;
      }
      status = pop_size_t(vm, &data_offset);
      if (status != EVM_OK) {
        return status;
      }
      status = pop_size_t(vm, &data_size);
      if (status != EVM_OK) {
        return status;
      }
      status = maybe_charge_copy_word_gas(vm, data_size);
      if (status != EVM_OK) {
        return status;
      }
      status = copy_to_memory(vm, memory_offset, data_offset, data_size,
                              vm->code, vm->code_size, false);
      if (status != EVM_OK) {
        return status;
      }
      break;
    }
    case OPCODE_GASPRICE:
      status = push_uint256(vm, &vm->gas_price);
      if (status != EVM_OK) {
        return status;
      }
      break;
    case OPCODE_EXTCODESIZE: {
      uint256_t account_address = uint256_zero();
      status = stack_require(vm, 1U);
      if (status != EVM_OK) {
        return status;
      }
      status = pop_uint256(vm, &account_address);
      if (status != EVM_OK) {
        return status;
      }
      account_address = normalize_address_word(&account_address);
      status = maybe_charge_account_access_gas(vm, &account_address);
      if (status != EVM_OK) {
        return status;
      }
      uint256_t value = uint256_zero();
      size_t code_size = 0;
      if (account_code_get(vm, &account_address, nullptr, &code_size,
                           nullptr)) {
#if SIZE_MAX > UINT64_MAX
        if (code_size > UINT64_MAX) {
          return EVM_ERR_RUNTIME;
        }
#endif
        value = uint256_from_u64((uint64_t)code_size);
      }
      status = push_uint256(vm, &value);
      if (status != EVM_OK) {
        return status;
      }
      break;
    }
    case OPCODE_EXTCODECOPY: {
      uint256_t account_address = uint256_zero();
      size_t memory_offset = 0;
      size_t data_offset = 0;
      size_t data_size = 0;
      status = stack_require(vm, 4U);
      if (status != EVM_OK) {
        return status;
      }
      status = pop_uint256(vm, &account_address);
      if (status != EVM_OK) {
        return status;
      }
      account_address = normalize_address_word(&account_address);
      status = maybe_charge_account_access_gas(vm, &account_address);
      if (status != EVM_OK) {
        return status;
      }
      status = pop_size_t(vm, &memory_offset);
      if (status != EVM_OK) {
        return status;
      }
      status = pop_size_t(vm, &data_offset);
      if (status != EVM_OK) {
        return status;
      }
      status = pop_size_t(vm, &data_size);
      if (status != EVM_OK) {
        return status;
      }
      status = maybe_charge_copy_word_gas(vm, data_size);
      if (status != EVM_OK) {
        return status;
      }
      const uint8_t *source = nullptr;
      size_t source_size = 0;
      (void)account_code_get(vm, &account_address, &source, &source_size,
                             nullptr);
      status = copy_to_memory(vm, memory_offset, data_offset, data_size, source,
                              source_size, false);
      if (status != EVM_OK) {
        return status;
      }
      break;
    }
    case OPCODE_RETURNDATASIZE: {
#if SIZE_MAX > UINT64_MAX
      if (vm->return_data_size > UINT64_MAX) {
        return EVM_ERR_RUNTIME;
      }
#endif
      uint256_t value = uint256_from_u64((uint64_t)vm->return_data_size);
      status = push_uint256(vm, &value);
      if (status != EVM_OK) {
        return status;
      }
      break;
    }
    case OPCODE_RETURNDATACOPY: {
      size_t memory_offset = 0;
      size_t data_offset = 0;
      size_t data_size = 0;
      status = stack_require(vm, 3U);
      if (status != EVM_OK) {
        return status;
      }
      status = pop_size_t(vm, &memory_offset);
      if (status != EVM_OK) {
        return status;
      }
      status = pop_size_t(vm, &data_offset);
      if (status != EVM_OK) {
        return status;
      }
      status = pop_size_t(vm, &data_size);
      if (status != EVM_OK) {
        return status;
      }
      status = maybe_charge_copy_word_gas(vm, data_size);
      if (status != EVM_OK) {
        return status;
      }
      status = copy_to_memory(vm, memory_offset, data_offset, data_size,
                              vm->return_data, vm->return_data_size, true);
      if (status != EVM_OK) {
        return status;
      }
      break;
    }
    case OPCODE_EXTCODEHASH: {
      uint256_t account_address = uint256_zero();
      status = stack_require(vm, 1U);
      if (status != EVM_OK) {
        return status;
      }
      status = pop_uint256(vm, &account_address);
      if (status != EVM_OK) {
        return status;
      }
      account_address = normalize_address_word(&account_address);
      status = maybe_charge_account_access_gas(vm, &account_address);
      if (status != EVM_OK) {
        return status;
      }
      uint256_t hash = account_code_hash_get(vm, &account_address);
      status = push_uint256(vm, &hash);
      if (status != EVM_OK) {
        return status;
      }
      break;
    }
    case OPCODE_BLOCKHASH: {
      uint256_t block_number = uint256_zero();
      status = stack_require(vm, 1U);
      if (status != EVM_OK) {
        return status;
      }
      status = pop_uint256(vm, &block_number);
      if (status != EVM_OK) {
        return status;
      }
      uint256_t hash = uint256_zero();
      if (uint256_fits_u64(&vm->block_number) &&
          uint256_fits_u64(&block_number)) {
        uint64_t current = vm->block_number.limbs[0];
        uint64_t requested = block_number.limbs[0];
        if (requested < current && (current - requested) <= 256U) {
          hash = block_hash_lookup(vm, &block_number);
        }
      }
      status = push_uint256(vm, &hash);
      if (status != EVM_OK) {
        return status;
      }
      break;
    }
    case OPCODE_COINBASE:
      status = push_uint256(vm, &vm->coinbase);
      if (status != EVM_OK) {
        return status;
      }
      break;
    case OPCODE_TIMESTAMP:
      status = push_uint256(vm, &vm->timestamp);
      if (status != EVM_OK) {
        return status;
      }
      break;
    case OPCODE_NUMBER:
      status = push_uint256(vm, &vm->block_number);
      if (status != EVM_OK) {
        return status;
      }
      break;
    case OPCODE_PREVRANDAO:
      status = push_uint256(vm, &vm->prev_randao);
      if (status != EVM_OK) {
        return status;
      }
      break;
    case OPCODE_GASLIMIT:
      status = push_uint256(vm, &vm->block_gas_limit);
      if (status != EVM_OK) {
        return status;
      }
      break;
    case OPCODE_CHAINID:
      status = push_uint256(vm, &vm->chain_id);
      if (status != EVM_OK) {
        return status;
      }
      break;
    case OPCODE_SELFBALANCE:
      status = push_uint256(vm, &vm->self_balance);
      if (status != EVM_OK) {
        return status;
      }
      break;
    case OPCODE_BASEFEE:
      status = push_uint256(vm, &vm->base_fee);
      if (status != EVM_OK) {
        return status;
      }
      break;
    case OPCODE_BLOBHASH:
    case OPCODE_BLOBBASEFEE:
      return invalid_opcode(vm);
    case OPCODE_KECCAK256: {
      size_t offset = 0;
      size_t data_size = 0;
      size_t end = 0;

      status = stack_require(vm, 2U);
      if (status != EVM_OK) {
        return status;
      }
      status = pop_size_t(vm, &offset);
      if (status != EVM_OK) {
        return status;
      }
      status = pop_size_t(vm, &data_size);
      if (status != EVM_OK) {
        return status;
      }

      status = maybe_charge_sha3_word_gas(vm, data_size);
      if (status != EVM_OK) {
        return status;
      }

      if (data_size > 0U) {
        if (add_size_overflow(offset, data_size, &end)) {
          return EVM_ERR_RUNTIME;
        }
        status = evm_memory_ensure(vm, end);
        if (status != EVM_OK) {
          return status;
        }
      }

      const union ethash_hash256 hash = ethash_keccak256(
          (data_size == 0U) ? nullptr : (vm->memory + offset), data_size);
      uint256_t result = uint256_zero();
      uint256_from_be_bytes(&result, hash.bytes);
      status = push_uint256(vm, &result);
      if (status != EVM_OK) {
        return status;
      }
      break;
    }
    case OPCODE_MLOAD: {
      size_t offset = 0;
      size_t end = 0;
      status = stack_require(vm, 1U);
      if (status != EVM_OK) {
        return status;
      }
      status = pop_size_t(vm, &offset);
      if (status != EVM_OK) {
        return status;
      }
      if (add_size_overflow(offset, 32U, &end)) {
        return EVM_ERR_RUNTIME;
      }
      status = evm_memory_ensure(vm, end);
      if (status != EVM_OK) {
        return status;
      }

      uint8_t bytes[32];
      memcpy(bytes, vm->memory + offset, 32U);
      uint256_t value = uint256_zero();
      uint256_from_be_bytes(&value, bytes);
      status = push_uint256(vm, &value);
      if (status != EVM_OK) {
        return status;
      }
      break;
    }
    case OPCODE_MSTORE: {
      size_t offset = 0;
      size_t end = 0;
      uint256_t value = uint256_zero();

      status = stack_require(vm, 2U);
      if (status != EVM_OK) {
        return status;
      }
      status = pop_size_t(vm, &offset);
      if (status != EVM_OK) {
        return status;
      }
      status = pop_uint256(vm, &value);
      if (status != EVM_OK) {
        return status;
      }
      if (add_size_overflow(offset, 32U, &end)) {
        return EVM_ERR_RUNTIME;
      }
      status = evm_memory_ensure(vm, end);
      if (status != EVM_OK) {
        return status;
      }

      uint8_t bytes[32];
      uint256_to_be_bytes(&value, bytes);
      memcpy(vm->memory + offset, bytes, 32U);
      break;
    }
    case OPCODE_MSTORE8: {
      size_t offset = 0;
      size_t end = 0;
      uint256_t value = uint256_zero();

      status = stack_require(vm, 2U);
      if (status != EVM_OK) {
        return status;
      }
      status = pop_size_t(vm, &offset);
      if (status != EVM_OK) {
        return status;
      }
      status = pop_uint256(vm, &value);
      if (status != EVM_OK) {
        return status;
      }
      if (add_size_overflow(offset, 1U, &end)) {
        return EVM_ERR_RUNTIME;
      }
      status = evm_memory_ensure(vm, end);
      if (status != EVM_OK) {
        return status;
      }

      vm->memory[offset] = (uint8_t)(value.limbs[0] & 0xffU);
      break;
    }
    case OPCODE_SLOAD: {
      uint256_t key = uint256_zero();
      status = stack_require(vm, 1U);
      if (status != EVM_OK) {
        return status;
      }
      status = pop_uint256(vm, &key);
      if (status != EVM_OK) {
        return status;
      }
      bool was_warm = false;
      status = warm_slot_mark(vm, &vm->address, &key, &was_warm);
      if (status != EVM_OK) {
        return status;
      }
      status = charge_gas(vm, was_warm ? GAS_SLOAD_WARM : GAS_SLOAD_COLD);
      if (status != EVM_OK) {
        return status;
      }
      uint256_t value = storage_get(vm, &key);
      status = push_uint256(vm, &value);
      if (status != EVM_OK) {
        return status;
      }
      break;
    }
    case OPCODE_SSTORE: {
      if (vm->is_static_context) {
        return write_protection(vm);
      }
      uint256_t key = uint256_zero();
      uint256_t value = uint256_zero();
      status = stack_require(vm, 2U);
      if (status != EVM_OK) {
        return status;
      }
      status = pop_uint256(vm, &key);
      if (status != EVM_OK) {
        return status;
      }
      status = pop_uint256(vm, &value);
      if (status != EVM_OK) {
        return status;
      }
      if (vm->gas_remaining <= GAS_CALL_STIPEND) {
        return out_of_gas(vm);
      }
      // EIP-2200/2929/3529 SSTORE accounting lives in one helper.
      status = sstore_berlin(vm, &key, &value);
      if (status != EVM_OK) {
        return status;
      }
      break;
    }
    case OPCODE_TLOAD:
    case OPCODE_TSTORE:
    case OPCODE_MCOPY:
      return invalid_opcode(vm);
    case OPCODE_MSIZE: {
      uint256_t size_word = uint256_from_u64((uint64_t)vm->memory_size);
      status = push_uint256(vm, &size_word);
      if (status != EVM_OK) {
        return status;
      }
      break;
    }
    case OPCODE_GAS: {
      uint256_t remaining = uint256_from_u64(vm->gas_remaining);
      status = push_uint256(vm, &remaining);
      if (status != EVM_OK) {
        return status;
      }
      break;
    }
    case OPCODE_JUMPDEST:
      break;
    case OPCODE_LOG0:
    case OPCODE_LOG1:
    case OPCODE_LOG2:
    case OPCODE_LOG3:
    case OPCODE_LOG4: {
      if (vm->is_static_context) {
        return write_protection(vm);
      }
      size_t topics_count = (size_t)(opcode - OPCODE_LOG0);
      size_t offset = 0;
      size_t data_size = 0;
      size_t end = 0;
      uint256_t topics[4] = {uint256_zero(), uint256_zero(), uint256_zero(),
                             uint256_zero()};

      status = stack_require(vm, 2U + topics_count);
      if (status != EVM_OK) {
        return status;
      }
      status = pop_size_t(vm, &offset);
      if (status != EVM_OK) {
        return status;
      }
      status = pop_size_t(vm, &data_size);
      if (status != EVM_OK) {
        return status;
      }
      for (size_t i = 0; i < topics_count; ++i) {
        status = pop_uint256(vm, &topics[i]);
        if (status != EVM_OK) {
          return status;
        }
      }

      if (data_size > 0U) {
        if (add_size_overflow(offset, data_size, &end)) {
          return EVM_ERR_RUNTIME;
        }
      }

      uint64_t log_gas = GAS_LOG + (uint64_t)topics_count * GAS_LOG_TOPIC;
      if (data_size > (size_t)((UINT64_MAX - log_gas) / GAS_LOG_DATA)) {
        return out_of_gas(vm);
      }
      log_gas += (uint64_t)data_size * GAS_LOG_DATA;
      status = charge_gas(vm, log_gas);
      if (status != EVM_OK) {
        return status;
      }

      if (data_size > 0U) {
        status = evm_memory_ensure(vm, end);
        if (status != EVM_OK) {
          return status;
        }
      }

      status = append_log(vm, topics, topics_count,
                          (data_size == 0U) ? nullptr : (vm->memory + offset),
                          data_size);
      if (status != EVM_OK) {
        return status;
      }
      break;
    }
    case OPCODE_CREATE:
    case OPCODE_CREATE2: {
      if (vm->is_static_context) {
        return write_protection(vm);
      }
      uint256_t endowment = uint256_zero();
      size_t offset = 0;
      size_t data_size = 0;
      uint256_t salt = uint256_zero();
      size_t required = (opcode == OPCODE_CREATE2) ? 4U : 3U;

      status = stack_require(vm, required);
      if (status != EVM_OK) {
        return status;
      }
      status = pop_uint256(vm, &endowment);
      if (status != EVM_OK) {
        return status;
      }
      status = pop_size_t(vm, &offset);
      if (status != EVM_OK) {
        return status;
      }
      status = pop_size_t(vm, &data_size);
      if (status != EVM_OK) {
        return status;
      }
      if (opcode == OPCODE_CREATE2) {
        status = pop_uint256(vm, &salt);
        if (status != EVM_OK) {
          return status;
        }
      }

      status = maybe_charge_initcode_word_gas(vm, data_size);
      if (status != EVM_OK) {
        return status;
      }
      if (opcode == OPCODE_CREATE2) {
        status = maybe_charge_create2_hash_gas(vm, data_size);
        if (status != EVM_OK) {
          return status;
        }
      }
      status = ensure_memory_range(vm, offset, data_size);
      if (status != EVM_OK) {
        return status;
      }

      // CREATE failure due to insufficient balance is non-exceptional.
      if (uint256_cmp(&vm->self_balance, &endowment) < 0) {
        status = set_return_data_bytes(vm, nullptr, 0U);
        if (status != EVM_OK) {
          return status;
        }
        uint256_t failed_address = uint256_zero();
        status = push_uint256(vm, &failed_address);
        if (status != EVM_OK) {
          return status;
        }
        break;
      }

      uint8_t *init_code = nullptr;
      if (data_size <= MAX_INITCODE_SIZE) {
        status = copy_memory_slice(vm, offset, data_size, &init_code);
        if (status != EVM_OK) {
          return status;
        }
      }

      uint64_t sender_nonce = 0;
      status = account_nonce_get(vm, &vm->address, &sender_nonce);
      if (status != EVM_OK) {
        free(init_code);
        return status;
      }

      uint64_t forwarded_gas = 0;
      status = charge_create_forwarded_gas(vm, &forwarded_gas);
      if (status != EVM_OK) {
        free(init_code);
        return status;
      }

      uint256_t created_address = uint256_zero();
      status =
          execute_create(vm, opcode, forwarded_gas, sender_nonce, init_code,
                         data_size, &endowment, &salt, &created_address);
      free(init_code);
      if (status != EVM_OK) {
        return status;
      }

      status = account_nonce_increment(vm, &vm->address);
      if (status != EVM_OK) {
        return status;
      }

      status = push_uint256(vm, &created_address);
      if (status != EVM_OK) {
        return status;
      }
      break;
    }
    case OPCODE_CALL:
    case OPCODE_CALLCODE: {
      uint256_t call_gas = uint256_zero();
      uint256_t target = uint256_zero();
      uint256_t value = uint256_zero();
      size_t input_offset = 0;
      size_t input_size = 0;
      size_t output_offset = 0;
      size_t output_size = 0;

      status = stack_require(vm, 7U);
      if (status != EVM_OK) {
        return status;
      }
      status = pop_uint256(vm, &call_gas);
      if (status != EVM_OK) {
        return status;
      }
      status = pop_uint256(vm, &target);
      if (status != EVM_OK) {
        return status;
      }
      target = normalize_address_word(&target);
      status = maybe_charge_account_access_gas(vm, &target);
      if (status != EVM_OK) {
        return status;
      }
      status = pop_uint256(vm, &value);
      if (status != EVM_OK) {
        return status;
      }
      if (vm->is_static_context && !uint256_is_zero(&value)) {
        return write_protection(vm);
      }
      status = pop_size_t(vm, &input_offset);
      if (status != EVM_OK) {
        return status;
      }
      status = pop_size_t(vm, &input_size);
      if (status != EVM_OK) {
        return status;
      }
      status = pop_size_t(vm, &output_offset);
      if (status != EVM_OK) {
        return status;
      }
      status = pop_size_t(vm, &output_size);
      if (status != EVM_OK) {
        return status;
      }

      status = ensure_memory_range(vm, input_offset, input_size);
      if (status != EVM_OK) {
        return status;
      }
      status = ensure_memory_range(vm, output_offset, output_size);
      if (status != EVM_OK) {
        return status;
      }

      bool has_value_transfer = !uint256_is_zero(&value);
      const uint256_t *new_account_target =
          (opcode == OPCODE_CALL) ? &target : nullptr;
      status =
          charge_call_extra_gas(vm, has_value_transfer, new_account_target);
      if (status != EVM_OK) {
        return status;
      }

      // CALL/CALLCODE with insufficient funds fails and pushes 0, but does not
      // halt the parent frame.
      if (uint256_cmp(&vm->self_balance, &value) < 0) {
        status = set_return_data_bytes(vm, nullptr, 0U);
        if (status != EVM_OK) {
          return status;
        }
        status = copy_return_data_to_memory(vm, output_offset, output_size);
        if (status != EVM_OK) {
          return status;
        }
        uint256_t call_success = uint256_zero();
        status = push_uint256(vm, &call_success);
        if (status != EVM_OK) {
          return status;
        }
        break;
      }

      uint8_t *input_data = nullptr;
      status = copy_memory_slice(vm, input_offset, input_size, &input_data);
      if (status != EVM_OK) {
        return status;
      }

      uint64_t gas_forwarded = 0;
      status = charge_call_forwarded_gas(vm, &call_gas, has_value_transfer,
                                         &gas_forwarded);
      if (status != EVM_OK) {
        free(input_data);
        return status;
      }

      bool call_succeeded = false;
      status = execute_message_call(vm, opcode, gas_forwarded, &target, &value,
                                    input_data, input_size, &call_succeeded);
      free(input_data);
      if (status != EVM_OK) {
        return status;
      }

      status = copy_return_data_to_memory(vm, output_offset, output_size);
      if (status != EVM_OK) {
        return status;
      }

      uint256_t call_success = uint256_from_u64(call_succeeded ? 1U : 0U);
      status = push_uint256(vm, &call_success);
      if (status != EVM_OK) {
        return status;
      }
      break;
    }
    case OPCODE_DELEGATECALL:
    case OPCODE_STATICCALL: {
      uint256_t call_gas = uint256_zero();
      uint256_t target = uint256_zero();
      size_t input_offset = 0;
      size_t input_size = 0;
      size_t output_offset = 0;
      size_t output_size = 0;

      status = stack_require(vm, 6U);
      if (status != EVM_OK) {
        return status;
      }
      status = pop_uint256(vm, &call_gas);
      if (status != EVM_OK) {
        return status;
      }
      status = pop_uint256(vm, &target);
      if (status != EVM_OK) {
        return status;
      }
      target = normalize_address_word(&target);
      status = maybe_charge_account_access_gas(vm, &target);
      if (status != EVM_OK) {
        return status;
      }
      status = pop_size_t(vm, &input_offset);
      if (status != EVM_OK) {
        return status;
      }
      status = pop_size_t(vm, &input_size);
      if (status != EVM_OK) {
        return status;
      }
      status = pop_size_t(vm, &output_offset);
      if (status != EVM_OK) {
        return status;
      }
      status = pop_size_t(vm, &output_size);
      if (status != EVM_OK) {
        return status;
      }

      status = ensure_memory_range(vm, input_offset, input_size);
      if (status != EVM_OK) {
        return status;
      }
      status = ensure_memory_range(vm, output_offset, output_size);
      if (status != EVM_OK) {
        return status;
      }

      uint8_t *input_data = nullptr;
      status = copy_memory_slice(vm, input_offset, input_size, &input_data);
      if (status != EVM_OK) {
        return status;
      }

      status = charge_call_extra_gas(vm, false, nullptr);
      if (status != EVM_OK) {
        free(input_data);
        return status;
      }

      uint64_t gas_forwarded = 0;
      status = charge_call_forwarded_gas(vm, &call_gas, false, &gas_forwarded);
      if (status != EVM_OK) {
        free(input_data);
        return status;
      }

      bool call_succeeded = false;
      status = execute_message_call(vm, opcode, gas_forwarded, &target, nullptr,
                                    input_data, input_size, &call_succeeded);
      free(input_data);
      if (status != EVM_OK) {
        return status;
      }

      status = copy_return_data_to_memory(vm, output_offset, output_size);
      if (status != EVM_OK) {
        return status;
      }

      uint256_t call_success = uint256_from_u64(call_succeeded ? 1U : 0U);
      status = push_uint256(vm, &call_success);
      if (status != EVM_OK) {
        return status;
      }
      break;
    }
    case OPCODE_RETURN:
    case OPCODE_REVERT: {
      size_t offset = 0;
      size_t data_size = 0;

      status = stack_require(vm, 2U);
      if (status != EVM_OK) {
        return status;
      }
      status = pop_size_t(vm, &offset);
      if (status != EVM_OK) {
        return status;
      }
      status = pop_size_t(vm, &data_size);
      if (status != EVM_OK) {
        return status;
      }

      status = set_return_data(vm, offset, data_size);
      if (status != EVM_OK) {
        return status;
      }

      if (opcode == OPCODE_REVERT) {
        // Revert only this frame snapshot: storage, transient storage, logs,
        // and refund delta.
        storage_rollback(vm);
        vm->transient_storage_count = 0;
        rollback_logs(vm, logs_start_count);
        vm->refund_counter = refund_start;
        return EVM_ERR_REVERT;
      }

      return maybe_apply_refund(vm);
    }
    case OPCODE_SELFDESTRUCT: {
      if (vm->is_static_context) {
        return write_protection(vm);
      }
      uint256_t beneficiary = uint256_zero();
      status = stack_require(vm, 1U);
      if (status != EVM_OK) {
        return status;
      }
      status = pop_uint256(vm, &beneficiary);
      if (status != EVM_OK) {
        return status;
      }
      beneficiary = normalize_address_word(&beneficiary);
      status = maybe_charge_account_access_gas(vm, &beneficiary);
      if (status != EVM_OK) {
        return status;
      }

      bool beneficiary_is_non_empty = false;
      if (uint256_cmp(&beneficiary, &vm->address) == 0) {
        uint64_t nonce = 0U;
        EVM_RuntimeAccount self_account_snapshot;
        if (runtime_account_read(vm, &vm->address, &self_account_snapshot)) {
          nonce = self_account_snapshot.nonce;
        }
        beneficiary_is_non_empty =
            nonce != 0U || !uint256_is_zero(&vm->self_balance) ||
            vm->code_size != 0U;
      } else {
        EVM_RuntimeAccount beneficiary_snapshot;
        if (runtime_account_read(vm, &beneficiary, &beneficiary_snapshot)) {
          beneficiary_is_non_empty =
              beneficiary_snapshot.nonce != 0U ||
              !uint256_is_zero(&beneficiary_snapshot.balance) ||
              beneficiary_snapshot.code_size != 0U;
        }
      }

      if (!beneficiary_is_non_empty && !uint256_is_zero(&vm->self_balance)) {
        status = charge_gas(vm, GAS_CALL_NEW_ACCOUNT);
        if (status != EVM_OK) {
          return status;
        }
      }

      bool beneficiary_is_self = uint256_cmp(&beneficiary, &vm->address) == 0;
      if (!uint256_is_zero(&vm->self_balance) && !beneficiary_is_self) {
        status = account_credit(vm, &beneficiary, &vm->self_balance);
        if (status != EVM_OK) {
          return status;
        }
      }
      if (!beneficiary_is_self) {
        vm->self_balance = uint256_zero();
      }

      if (beneficiary_is_self) {
        vm->self_balance = uint256_zero();
      }
      status = account_mark_selfdestruct(vm, &vm->address);
      if (status != EVM_OK) {
        return status;
      }
      return maybe_apply_refund(vm);
    }
    case OPCODE_INVALID:
      return invalid_opcode(vm);
    default:
      // Reserved/undefined opcode.
      return invalid_opcode(vm);
    }
  }

  return maybe_apply_refund(vm);
}
