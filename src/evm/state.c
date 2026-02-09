#include <stdlib.h>
#include <string.h>

#include "evm/state_internal.h"
#include "keccak.h"

uint256_t storage_get(const EVM_State *vm, const uint256_t *key) {
  size_t index = 0;
  if (storage_find(vm, key, &index)) {
    return vm->storage[index].value;
  }
  return uint256_zero();
}

EVM_Status storage_set(EVM_State *vm, const uint256_t *key,
                              const uint256_t *value, const uint256_t *original,
                              bool existed_at_start,
                              const uint256_t *tx_original,
                              bool existed_at_transaction_start) {
  size_t index = 0;
  if (storage_find(vm, key, &index)) {
    vm->storage[index].value = *value;
    return EVM_OK;
  }

  if (vm->storage_count == vm->storage_capacity) {
    EVM_Status status =
        reserve_realloc_array((void **)&vm->storage, &vm->storage_capacity,
                              vm->storage_count + 1U, sizeof(EVM_StorageEntry));
    if (status != EVM_OK) {
      return status;
    }
  }

  vm->storage[vm->storage_count].key = *key;
  vm->storage[vm->storage_count].value = *value;
  vm->storage[vm->storage_count].original = *original;
  vm->storage[vm->storage_count].existed_at_start = existed_at_start;
  vm->storage[vm->storage_count].tx_original = *tx_original;
  vm->storage[vm->storage_count].existed_at_transaction_start =
      existed_at_transaction_start;
  vm->storage_count += 1U;
  size_t inserted_index = vm->storage_count - 1U;
  // Keep the open-addressing index table below ~50% load to limit probes.
  if (vm->storage_index_table == nullptr ||
      vm->storage_index_table_capacity == 0U ||
      vm->storage_count > (vm->storage_index_table_capacity / 2U)) {
    return storage_index_rebuild(vm);
  }
  return storage_index_insert(vm, inserted_index);
}

void storage_snapshot_originals(EVM_State *vm) {
  for (size_t i = 0; i < vm->storage_count; ++i) {
    vm->storage[i].original = vm->storage[i].value;
    vm->storage[i].existed_at_start = true;
  }
}

void storage_snapshot_transaction_originals(EVM_State *vm) {
  for (size_t i = 0; i < vm->storage_count; ++i) {
    vm->storage[i].tx_original = vm->storage[i].value;
    vm->storage[i].existed_at_transaction_start = true;
  }
}

void storage_rollback(EVM_State *vm) {
  size_t write_index = 0;
  for (size_t i = 0; i < vm->storage_count; ++i) {
    // Entries created in this frame are dropped; prior entries restore
    // original values and are compacted in place.
    if (!vm->storage[i].existed_at_start) {
      continue;
    }
    vm->storage[i].value = vm->storage[i].original;
    vm->storage[write_index++] = vm->storage[i];
  }
  vm->storage_count = write_index;
  free(vm->storage_index_table);
  vm->storage_index_table = nullptr;
  vm->storage_index_table_capacity = 0;
}

static bool warm_slot_find(const EVM_State *vm, const uint256_t *address,
                           const uint256_t *key) {
  if (vm->warm_slots_index_table != nullptr &&
      vm->warm_slots_index_table_capacity != 0U) {
    size_t mask = vm->warm_slots_index_table_capacity - 1U;
    size_t slot = hash_access_entry(address, key) & mask;
    for (size_t probe = 0U; probe < vm->warm_slots_index_table_capacity;
         ++probe) {
      size_t entry = vm->warm_slots_index_table[slot];
      if (entry == 0U) {
        break;
      }
      size_t index = entry - 1U;
      if (index < vm->warm_slots_count &&
          uint256_cmp(&vm->warm_slots[index].address, address) == 0 &&
          uint256_cmp(&vm->warm_slots[index].key, key) == 0) {
        return true;
      }
      slot = (slot + 1U) & mask;
    }
  }

  for (size_t i = 0; i < vm->warm_slots_count; ++i) {
    if (uint256_cmp(&vm->warm_slots[i].address, address) == 0 &&
        uint256_cmp(&vm->warm_slots[i].key, key) == 0) {
      return true;
    }
  }
  return false;
}

static EVM_Status warm_slots_index_insert(EVM_State *vm, size_t index) {
  if (vm->warm_slots_index_table == nullptr ||
      vm->warm_slots_index_table_capacity == 0U ||
      index >= vm->warm_slots_count) {
    return EVM_ERR_INTERNAL;
  }

  size_t mask = vm->warm_slots_index_table_capacity - 1U;
  const EVM_AccessEntry *entry = &vm->warm_slots[index];
  size_t slot = hash_access_entry(&entry->address, &entry->key) & mask;
  for (size_t probe = 0U; probe < vm->warm_slots_index_table_capacity;
       ++probe) {
    size_t slot_entry = vm->warm_slots_index_table[slot];
    if (slot_entry == 0U) {
      vm->warm_slots_index_table[slot] = index + 1U;
      return EVM_OK;
    }

    size_t existing_index = slot_entry - 1U;
    if (existing_index < vm->warm_slots_count &&
        uint256_cmp(&vm->warm_slots[existing_index].address, &entry->address) ==
            0 &&
        uint256_cmp(&vm->warm_slots[existing_index].key, &entry->key) == 0) {
      vm->warm_slots_index_table[slot] = index + 1U;
      return EVM_OK;
    }
    slot = (slot + 1U) & mask;
  }

  return EVM_ERR_INTERNAL;
}

static EVM_Status warm_slots_index_rebuild(EVM_State *vm) {
  EVM_Status status = index_table_resize(&vm->warm_slots_index_table,
                                         &vm->warm_slots_index_table_capacity,
                                         vm->warm_slots_count);
  if (status != EVM_OK || vm->warm_slots_count == 0U) {
    return status;
  }

  for (size_t i = 0; i < vm->warm_slots_count; ++i) {
    status = warm_slots_index_insert(vm, i);
    if (status != EVM_OK) {
      free(vm->warm_slots_index_table);
      vm->warm_slots_index_table = nullptr;
      vm->warm_slots_index_table_capacity = 0U;
      return status;
    }
  }
  return EVM_OK;
}

EVM_Status warm_slot_mark(EVM_State *vm, const uint256_t *address,
                                 const uint256_t *key, bool *was_warm) {
  *was_warm = warm_slot_find(vm, address, key);
  if (*was_warm) {
    return EVM_OK;
  }

  if (vm->warm_slots_count == vm->warm_slots_capacity) {
    EVM_Status status = reserve_realloc_array(
        (void **)&vm->warm_slots, &vm->warm_slots_capacity,
        vm->warm_slots_count + 1U, sizeof(EVM_AccessEntry));
    if (status != EVM_OK) {
      return status;
    }
  }

  vm->warm_slots[vm->warm_slots_count].address = *address;
  vm->warm_slots[vm->warm_slots_count].key = *key;
  vm->warm_slots_count += 1U;
  size_t inserted_index = vm->warm_slots_count - 1U;
  // Mirror append-only list into hash index for O(1)-ish warm checks.
  if (vm->warm_slots_index_table == nullptr ||
      vm->warm_slots_index_table_capacity == 0U ||
      vm->warm_slots_count > (vm->warm_slots_index_table_capacity / 2U)) {
    return warm_slots_index_rebuild(vm);
  }
  return warm_slots_index_insert(vm, inserted_index);
}

EVM_Status warm_slots_clone(EVM_State *dst, const EVM_State *src) {
  free(dst->warm_slots);
  dst->warm_slots = nullptr;
  dst->warm_slots_count = 0;
  dst->warm_slots_capacity = 0;
  free(dst->warm_slots_index_table);
  dst->warm_slots_index_table = nullptr;
  dst->warm_slots_index_table_capacity = 0;

  if (src->warm_slots_count == 0U) {
    return EVM_OK;
  }
  if (src->warm_slots == nullptr) {
    return EVM_ERR_INTERNAL;
  }

  EVM_AccessEntry *entries =
      calloc(src->warm_slots_count, sizeof(EVM_AccessEntry));
  if (entries == nullptr) {
    return EVM_ERR_OOM;
  }
  memcpy(entries, src->warm_slots,
         src->warm_slots_count * sizeof(EVM_AccessEntry));

  dst->warm_slots = entries;
  dst->warm_slots_count = src->warm_slots_count;
  dst->warm_slots_capacity = src->warm_slots_count;
  return warm_slots_index_rebuild(dst);
}

void warm_slots_commit_from_child(EVM_State *parent, EVM_State *child) {
  free(parent->warm_slots);
  free(parent->warm_slots_index_table);
  parent->warm_slots = child->warm_slots;
  parent->warm_slots_count = child->warm_slots_count;
  parent->warm_slots_capacity = child->warm_slots_capacity;
  parent->warm_slots_index_table = child->warm_slots_index_table;
  parent->warm_slots_index_table_capacity =
      child->warm_slots_index_table_capacity;

  child->warm_slots = nullptr;
  child->warm_slots_count = 0;
  child->warm_slots_capacity = 0;
  child->warm_slots_index_table = nullptr;
  child->warm_slots_index_table_capacity = 0;
}

static bool warm_account_find(const EVM_State *vm, const uint256_t *address) {
  if (vm->warm_accounts_index_table != nullptr &&
      vm->warm_accounts_index_table_capacity != 0U) {
    size_t mask = vm->warm_accounts_index_table_capacity - 1U;
    size_t slot = hash_uint256_value(address) & mask;
    for (size_t probe = 0U; probe < vm->warm_accounts_index_table_capacity;
         ++probe) {
      size_t entry = vm->warm_accounts_index_table[slot];
      if (entry == 0U) {
        break;
      }
      size_t index = entry - 1U;
      if (index < vm->warm_accounts_count &&
          uint256_cmp(&vm->warm_accounts[index], address) == 0) {
        return true;
      }
      slot = (slot + 1U) & mask;
    }
  }

  for (size_t i = 0; i < vm->warm_accounts_count; ++i) {
    if (uint256_cmp(&vm->warm_accounts[i], address) == 0) {
      return true;
    }
  }
  return false;
}

static EVM_Status warm_accounts_index_insert(EVM_State *vm, size_t index) {
  if (vm->warm_accounts_index_table == nullptr ||
      vm->warm_accounts_index_table_capacity == 0U ||
      index >= vm->warm_accounts_count) {
    return EVM_ERR_INTERNAL;
  }

  size_t mask = vm->warm_accounts_index_table_capacity - 1U;
  const uint256_t *account = &vm->warm_accounts[index];
  size_t slot = hash_uint256_value(account) & mask;
  for (size_t probe = 0U; probe < vm->warm_accounts_index_table_capacity;
       ++probe) {
    size_t slot_entry = vm->warm_accounts_index_table[slot];
    if (slot_entry == 0U) {
      vm->warm_accounts_index_table[slot] = index + 1U;
      return EVM_OK;
    }

    size_t existing_index = slot_entry - 1U;
    if (existing_index < vm->warm_accounts_count &&
        uint256_cmp(&vm->warm_accounts[existing_index], account) == 0) {
      vm->warm_accounts_index_table[slot] = index + 1U;
      return EVM_OK;
    }
    slot = (slot + 1U) & mask;
  }

  return EVM_ERR_INTERNAL;
}

static EVM_Status warm_accounts_index_rebuild(EVM_State *vm) {
  EVM_Status status = index_table_resize(
      &vm->warm_accounts_index_table, &vm->warm_accounts_index_table_capacity,
      vm->warm_accounts_count);
  if (status != EVM_OK || vm->warm_accounts_count == 0U) {
    return status;
  }

  for (size_t i = 0; i < vm->warm_accounts_count; ++i) {
    status = warm_accounts_index_insert(vm, i);
    if (status != EVM_OK) {
      free(vm->warm_accounts_index_table);
      vm->warm_accounts_index_table = nullptr;
      vm->warm_accounts_index_table_capacity = 0U;
      return status;
    }
  }
  return EVM_OK;
}

EVM_Status warm_account_mark(EVM_State *vm, const uint256_t *address,
                                    bool *was_warm) {
  *was_warm = warm_account_find(vm, address);
  if (*was_warm) {
    return EVM_OK;
  }

  if (vm->warm_accounts_count == vm->warm_accounts_capacity) {
    EVM_Status status = reserve_realloc_array(
        (void **)&vm->warm_accounts, &vm->warm_accounts_capacity,
        vm->warm_accounts_count + 1U, sizeof(uint256_t));
    if (status != EVM_OK) {
      return status;
    }
  }

  vm->warm_accounts[vm->warm_accounts_count] = *address;
  vm->warm_accounts_count += 1U;
  size_t inserted_index = vm->warm_accounts_count - 1U;
  // Same strategy as warm slots: dense list + hash index.
  if (vm->warm_accounts_index_table == nullptr ||
      vm->warm_accounts_index_table_capacity == 0U ||
      vm->warm_accounts_count > (vm->warm_accounts_index_table_capacity / 2U)) {
    return warm_accounts_index_rebuild(vm);
  }
  return warm_accounts_index_insert(vm, inserted_index);
}

EVM_Status warm_accounts_clone(EVM_State *dst, const EVM_State *src) {
  free(dst->warm_accounts);
  dst->warm_accounts = nullptr;
  dst->warm_accounts_count = 0;
  dst->warm_accounts_capacity = 0;
  free(dst->warm_accounts_index_table);
  dst->warm_accounts_index_table = nullptr;
  dst->warm_accounts_index_table_capacity = 0;

  if (src->warm_accounts_count == 0U) {
    return EVM_OK;
  }
  if (src->warm_accounts == nullptr) {
    return EVM_ERR_INTERNAL;
  }

  uint256_t *accounts = calloc(src->warm_accounts_count, sizeof(uint256_t));
  if (accounts == nullptr) {
    return EVM_ERR_OOM;
  }
  memcpy(accounts, src->warm_accounts,
         src->warm_accounts_count * sizeof(uint256_t));

  dst->warm_accounts = accounts;
  dst->warm_accounts_count = src->warm_accounts_count;
  dst->warm_accounts_capacity = src->warm_accounts_count;
  return warm_accounts_index_rebuild(dst);
}

void warm_accounts_commit_from_child(EVM_State *parent,
                                            EVM_State *child) {
  free(parent->warm_accounts);
  free(parent->warm_accounts_index_table);
  parent->warm_accounts = child->warm_accounts;
  parent->warm_accounts_count = child->warm_accounts_count;
  parent->warm_accounts_capacity = child->warm_accounts_capacity;
  parent->warm_accounts_index_table = child->warm_accounts_index_table;
  parent->warm_accounts_index_table_capacity =
      child->warm_accounts_index_table_capacity;

  child->warm_accounts = nullptr;
  child->warm_accounts_count = 0;
  child->warm_accounts_capacity = 0;
  child->warm_accounts_index_table = nullptr;
  child->warm_accounts_index_table_capacity = 0;
}

static bool transient_storage_find(const EVM_State *vm, const uint256_t *key,
                                   size_t *index_out) {
  for (size_t i = 0; i < vm->transient_storage_count; ++i) {
    if (uint256_cmp(&vm->transient_storage[i].key, key) == 0) {
      *index_out = i;
      return true;
    }
  }
  return false;
}

uint256_t transient_storage_get(const EVM_State *vm,
                                       const uint256_t *key) {
  size_t index = 0;
  if (transient_storage_find(vm, key, &index)) {
    return vm->transient_storage[index].value;
  }
  return uint256_zero();
}

EVM_Status transient_storage_set(EVM_State *vm, const uint256_t *key,
                                        const uint256_t *value) {
  size_t index = 0;
  if (transient_storage_find(vm, key, &index)) {
    vm->transient_storage[index].value = *value;
    return EVM_OK;
  }

  if (vm->transient_storage_count == vm->transient_storage_capacity) {
    EVM_Status status = reserve_realloc_array(
        (void **)&vm->transient_storage, &vm->transient_storage_capacity,
        vm->transient_storage_count + 1U, sizeof(EVM_TransientEntry));
    if (status != EVM_OK) {
      return status;
    }
  }

  vm->transient_storage[vm->transient_storage_count].key = *key;
  vm->transient_storage[vm->transient_storage_count].value = *value;
  vm->transient_storage_count += 1U;
  return EVM_OK;
}

static const EVM_ExternalAccount *
find_external_account(const EVM_State *vm, const uint256_t *address) {
  for (size_t i = 0; i < vm->external_accounts_count; ++i) {
    if (uint256_cmp(&vm->external_accounts[i].address, address) == 0) {
      return &vm->external_accounts[i];
    }
  }
  return nullptr;
}

static bool uint256_add_overflow(const uint256_t *a, const uint256_t *b,
                                 uint256_t *out) {
  *out = uint256_add(a, b);
  return !uint256_is_zero(b) && uint256_cmp(out, a) < 0;
}

static bool runtime_account_find(const EVM_State *vm, const uint256_t *address,
                                 size_t *index_out) {
  for (size_t i = 0; i < vm->runtime_accounts_count; ++i) {
    if (uint256_cmp(&vm->runtime_accounts[i].address, address) == 0) {
      *index_out = i;
      return true;
    }
  }
  return false;
}

static void runtime_account_clear_code(EVM_RuntimeAccount *account) {
  if (account->code_owned) {
    free((void *)account->code);
  }
  account->code = nullptr;
  account->code_size = 0;
  account->code_hash = uint256_zero();
  account->code_owned = false;
}

static void runtime_account_clear_storage(EVM_RuntimeAccount *account) {
  free(account->storage);
  account->storage = nullptr;
  account->storage_count = 0;
  account->storage_capacity = 0;
}

static void
runtime_account_clear_transient_storage(EVM_RuntimeAccount *account) {
  free(account->transient_storage);
  account->transient_storage = nullptr;
  account->transient_storage_count = 0;
  account->transient_storage_capacity = 0;
}

static EVM_Status runtime_account_set_code(EVM_RuntimeAccount *account,
                                           const uint8_t *code,
                                           size_t code_size) {
  uint8_t *new_code = nullptr;
  if (code_size > 0U) {
    if (code == nullptr) {
      return EVM_ERR_INTERNAL;
    }
    new_code = calloc(code_size, sizeof(uint8_t));
    if (new_code == nullptr) {
      return EVM_ERR_OOM;
    }
    memcpy(new_code, code, code_size);
  }

  runtime_account_clear_code(account);
  account->code = new_code;
  account->code_size = code_size;
  account->code_owned = (code_size > 0U);
  account->destroyed = false;
  return EVM_OK;
}

static EVM_Status
runtime_account_set_storage_entries(EVM_RuntimeAccount *account,
                                    const EVM_StorageEntry *storage,
                                    size_t storage_count) {
  EVM_StorageEntry *new_storage = nullptr;
  if (storage_count > 0U) {
    if (storage == nullptr) {
      return EVM_ERR_INTERNAL;
    }
    new_storage = calloc(storage_count, sizeof(EVM_StorageEntry));
    if (new_storage == nullptr) {
      return EVM_ERR_OOM;
    }
    memcpy(new_storage, storage, storage_count * sizeof(EVM_StorageEntry));
  }

  runtime_account_clear_storage(account);
  account->storage = new_storage;
  account->storage_count = storage_count;
  account->storage_capacity = storage_count;
  return EVM_OK;
}

static EVM_Status
runtime_account_set_transient_entries(EVM_RuntimeAccount *account,
                                      const EVM_TransientEntry *entries,
                                      size_t entries_count) {
  EVM_TransientEntry *new_entries = nullptr;
  if (entries_count > 0U) {
    if (entries == nullptr) {
      return EVM_ERR_INTERNAL;
    }
    new_entries = calloc(entries_count, sizeof(EVM_TransientEntry));
    if (new_entries == nullptr) {
      return EVM_ERR_OOM;
    }
    memcpy(new_entries, entries, entries_count * sizeof(EVM_TransientEntry));
  }

  runtime_account_clear_transient_storage(account);
  account->transient_storage = new_entries;
  account->transient_storage_count = entries_count;
  account->transient_storage_capacity = entries_count;
  return EVM_OK;
}

EVM_Status runtime_account_ensure(EVM_State *vm,
                                         const uint256_t *address,
                                         EVM_RuntimeAccount **out_account) {
  size_t index = 0;
  if (runtime_account_find(vm, address, &index)) {
    *out_account = &vm->runtime_accounts[index];
    return EVM_OK;
  }

  if (vm->runtime_accounts_count == vm->runtime_accounts_capacity) {
    EVM_Status status = reserve_realloc_array(
        (void **)&vm->runtime_accounts, &vm->runtime_accounts_capacity,
        vm->runtime_accounts_count + 1U, sizeof(EVM_RuntimeAccount));
    if (status != EVM_OK) {
      return status;
    }
  }

  EVM_RuntimeAccount account;
  memset(&account, 0, sizeof(account));
  account.address = *address;
  account.balance = uint256_zero();
  account.code = nullptr;
  account.code_size = 0;
  account.code_hash = uint256_zero();
  account.nonce = 0;
  account.storage = nullptr;
  account.storage_count = 0;
  account.storage_capacity = 0;
  account.transient_storage = nullptr;
  account.transient_storage_count = 0;
  account.transient_storage_capacity = 0;
  account.code_owned = false;
  account.destroyed = false;
  account.selfdestruct_pending = false;
  account.created_in_transaction = false;

  const EVM_ExternalAccount *external = find_external_account(vm, address);
  if (external != nullptr) {
    account.balance = external->balance;
    account.code = external->code;
    account.code_size = external->code_size;
    account.code_hash = external->code_hash;
    account.nonce = external->nonce;
  }

  vm->runtime_accounts[vm->runtime_accounts_count] = account;
  *out_account = &vm->runtime_accounts[vm->runtime_accounts_count];
  vm->runtime_accounts_count += 1U;
  return EVM_OK;
}

bool runtime_account_read(const EVM_State *vm, const uint256_t *address,
                                 EVM_RuntimeAccount *out_account) {
  size_t index = 0;
  if (runtime_account_find(vm, address, &index)) {
    if (vm->runtime_accounts[index].destroyed) {
      return false;
    }
    *out_account = vm->runtime_accounts[index];
    return true;
  }

  const EVM_ExternalAccount *external = find_external_account(vm, address);
  if (external == nullptr) {
    return false;
  }

  memset(out_account, 0, sizeof(*out_account));
  out_account->address = external->address;
  out_account->balance = external->balance;
  out_account->code = external->code;
  out_account->code_size = external->code_size;
  out_account->code_hash = external->code_hash;
  out_account->nonce = external->nonce;
  out_account->storage = nullptr;
  out_account->storage_count = 0;
  out_account->storage_capacity = 0;
  out_account->transient_storage = nullptr;
  out_account->transient_storage_count = 0;
  out_account->transient_storage_capacity = 0;
  out_account->code_owned = false;
  out_account->destroyed = false;
  out_account->selfdestruct_pending = false;
  out_account->created_in_transaction = false;
  return true;
}

static uint256_t runtime_code_hash(const EVM_RuntimeAccount *account) {
  if (account == nullptr) {
    return uint256_zero();
  }
  if (!uint256_is_zero(&account->code_hash)) {
    return account->code_hash;
  }
  if (account->code_size > 0U && account->code == nullptr) {
    return uint256_zero();
  }

  const union ethash_hash256 hash =
      ethash_keccak256(account->code, account->code_size);
  uint256_t out = uint256_zero();
  uint256_from_be_bytes(&out, hash.bytes);
  return out;
}

uint256_t account_balance_get(const EVM_State *vm,
                                     const uint256_t *address) {
  if (uint256_cmp(address, &vm->address) == 0) {
    return vm->self_balance;
  }

  EVM_RuntimeAccount account;
  if (!runtime_account_read(vm, address, &account)) {
    return uint256_zero();
  }
  return account.balance;
}

bool account_code_get(const EVM_State *vm, const uint256_t *address,
                             const uint8_t **out_code, size_t *out_code_size,
                             uint256_t *out_balance) {
  if (uint256_cmp(address, &vm->address) == 0) {
    if (out_code != nullptr) {
      *out_code = vm->code;
    }
    if (out_code_size != nullptr) {
      *out_code_size = vm->code_size;
    }
    if (out_balance != nullptr) {
      *out_balance = vm->self_balance;
    }
    return true;
  }

  EVM_RuntimeAccount account;
  if (!runtime_account_read(vm, address, &account)) {
    if (out_code != nullptr) {
      *out_code = nullptr;
    }
    if (out_code_size != nullptr) {
      *out_code_size = 0U;
    }
    if (out_balance != nullptr) {
      *out_balance = uint256_zero();
    }
    return false;
  }
  if (out_code != nullptr) {
    *out_code = account.code;
  }
  if (out_code_size != nullptr) {
    *out_code_size = account.code_size;
  }
  if (out_balance != nullptr) {
    *out_balance = account.balance;
  }
  return true;
}

uint256_t account_code_hash_get(const EVM_State *vm,
                                       const uint256_t *address) {
  if (uint256_cmp(address, &vm->address) == 0) {
    EVM_RuntimeAccount current;
    memset(&current, 0, sizeof(current));
    current.code = vm->code;
    current.code_size = vm->code_size;
    return runtime_code_hash(&current);
  }

  EVM_RuntimeAccount account;
  if (!runtime_account_read(vm, address, &account)) {
    return uint256_zero();
  }
  return runtime_code_hash(&account);
}

EVM_Status account_credit(EVM_State *vm, const uint256_t *address,
                                 const uint256_t *delta) {
  if (uint256_is_zero(delta)) {
    return EVM_OK;
  }

  EVM_RuntimeAccount *account = nullptr;
  EVM_Status status = runtime_account_ensure(vm, address, &account);
  if (status != EVM_OK) {
    return status;
  }
  account->destroyed = false;

  uint256_t next_balance = uint256_zero();
  if (uint256_add_overflow(&account->balance, delta, &next_balance)) {
    return EVM_ERR_RUNTIME;
  }
  account->balance = next_balance;
  return EVM_OK;
}

static EVM_Status account_debit(EVM_State *vm, const uint256_t *address,
                                const uint256_t *delta) {
  if (uint256_is_zero(delta)) {
    return EVM_OK;
  }

  EVM_RuntimeAccount *account = nullptr;
  EVM_Status status = runtime_account_ensure(vm, address, &account);
  if (status != EVM_OK) {
    return status;
  }

  if (uint256_cmp(&account->balance, delta) < 0) {
    return EVM_ERR_RUNTIME;
  }

  account->balance = uint256_sub(&account->balance, delta);
  account->destroyed = false;
  return EVM_OK;
}

EVM_Status account_transfer(EVM_State *vm, const uint256_t *from,
                                   const uint256_t *to,
                                   const uint256_t *delta) {
  if (delta == nullptr || uint256_is_zero(delta) ||
      uint256_cmp(from, to) == 0) {
    return EVM_OK;
  }

  EVM_Status status = account_debit(vm, from, delta);
  if (status != EVM_OK) {
    return status;
  }
  return account_credit(vm, to, delta);
}

EVM_Status account_deploy_contract(EVM_State *vm,
                                          const uint256_t *address,
                                          const uint8_t *runtime_code,
                                          size_t runtime_code_size,
                                          const uint256_t *balance) {
  EVM_RuntimeAccount *account = nullptr;
  EVM_Status status = runtime_account_ensure(vm, address, &account);
  if (status != EVM_OK) {
    return status;
  }

  status = runtime_account_set_code(account, runtime_code, runtime_code_size);
  if (status != EVM_OK) {
    return status;
  }
  account->balance = *balance;
  account->nonce = 1U;
  account->destroyed = false;
  account->created_in_transaction = true;
  return EVM_OK;
}

EVM_Status account_nonce_get(EVM_State *vm, const uint256_t *address,
                                    uint64_t *out_nonce) {
  if (out_nonce == nullptr) {
    return EVM_ERR_INTERNAL;
  }

  EVM_RuntimeAccount *account = nullptr;
  EVM_Status status = runtime_account_ensure(vm, address, &account);
  if (status != EVM_OK) {
    return status;
  }

  *out_nonce = account->nonce;
  return EVM_OK;
}

EVM_Status account_nonce_increment(EVM_State *vm,
                                          const uint256_t *address) {
  EVM_RuntimeAccount *account = nullptr;
  EVM_Status status = runtime_account_ensure(vm, address, &account);
  if (status != EVM_OK) {
    return status;
  }

  if (account->nonce == UINT64_MAX) {
    return EVM_ERR_RUNTIME;
  }

  account->nonce += 1U;
  account->destroyed = false;
  return EVM_OK;
}

EVM_Status account_mark_selfdestruct(EVM_State *vm,
                                            const uint256_t *address) {
  EVM_RuntimeAccount *account = nullptr;
  EVM_Status status = runtime_account_ensure(vm, address, &account);
  if (status != EVM_OK) {
    return status;
  }

  account->selfdestruct_pending = true;
  return EVM_OK;
}

EVM_Status account_mark_destroyed(EVM_State *vm,
                                         const uint256_t *address) {
  EVM_RuntimeAccount *account = nullptr;
  EVM_Status status = runtime_account_ensure(vm, address, &account);
  if (status != EVM_OK) {
    return status;
  }
  runtime_account_clear_code(account);
  runtime_account_clear_storage(account);
  runtime_account_clear_transient_storage(account);
  account->balance = uint256_zero();
  account->destroyed = true;
  account->selfdestruct_pending = false;
  account->created_in_transaction = false;
  return EVM_OK;
}

EVM_Status runtime_accounts_apply_selfdestructs(EVM_State *vm) {
  for (size_t i = 0; i < vm->runtime_accounts_count; ++i) {
    EVM_RuntimeAccount *account = &vm->runtime_accounts[i];
    if (!account->selfdestruct_pending) {
      continue;
    }

    runtime_account_clear_code(account);
    runtime_account_clear_storage(account);
    runtime_account_clear_transient_storage(account);
    account->balance = uint256_zero();
    account->destroyed = true;
    account->selfdestruct_pending = false;
    account->created_in_transaction = false;
  }
  return EVM_OK;
}

void runtime_accounts_release(EVM_State *vm) {
  if (vm->runtime_accounts == nullptr) {
    vm->runtime_accounts_count = 0;
    vm->runtime_accounts_capacity = 0;
    return;
  }

  for (size_t i = 0; i < vm->runtime_accounts_count; ++i) {
    runtime_account_clear_code(&vm->runtime_accounts[i]);
    runtime_account_clear_storage(&vm->runtime_accounts[i]);
    runtime_account_clear_transient_storage(&vm->runtime_accounts[i]);
  }
  free(vm->runtime_accounts);
  vm->runtime_accounts = nullptr;
  vm->runtime_accounts_count = 0;
  vm->runtime_accounts_capacity = 0;
}

void runtime_accounts_snapshot_transaction_originals(EVM_State *vm) {
  for (size_t account_index = 0; account_index < vm->runtime_accounts_count;
       ++account_index) {
    EVM_RuntimeAccount *account = &vm->runtime_accounts[account_index];
    for (size_t storage_index = 0; storage_index < account->storage_count;
         ++storage_index) {
      account->storage[storage_index].tx_original =
          account->storage[storage_index].value;
      account->storage[storage_index].existed_at_transaction_start = true;
    }
  }
}

static EVM_Status runtime_account_copy(EVM_RuntimeAccount *dst,
                                       const EVM_RuntimeAccount *src) {
  memset(dst, 0, sizeof(*dst));
  dst->address = src->address;
  dst->balance = src->balance;
  dst->code_hash = src->code_hash;
  dst->nonce = src->nonce;
  dst->destroyed = src->destroyed;
  dst->selfdestruct_pending = src->selfdestruct_pending;
  dst->created_in_transaction = src->created_in_transaction;

  EVM_Status status = runtime_account_set_code(dst, src->code, src->code_size);
  if (status != EVM_OK) {
    return status;
  }
  dst->code_hash = src->code_hash;

  status = runtime_account_set_storage_entries(dst, src->storage,
                                               src->storage_count);
  if (status != EVM_OK) {
    runtime_account_clear_code(dst);
    return status;
  }

  status = runtime_account_set_transient_entries(dst, src->transient_storage,
                                                 src->transient_storage_count);
  if (status != EVM_OK) {
    runtime_account_clear_storage(dst);
    runtime_account_clear_code(dst);
    return status;
  }

  dst->destroyed = src->destroyed;
  dst->selfdestruct_pending = src->selfdestruct_pending;
  dst->created_in_transaction = src->created_in_transaction;
  return EVM_OK;
}

EVM_Status runtime_accounts_clone(EVM_State *dst, const EVM_State *src) {
  runtime_accounts_release(dst);
  if (src->runtime_accounts_count == 0U) {
    return EVM_OK;
  }

  EVM_RuntimeAccount *accounts =
      calloc(src->runtime_accounts_count, sizeof(EVM_RuntimeAccount));
  if (accounts == nullptr) {
    return EVM_ERR_OOM;
  }

  dst->runtime_accounts = accounts;
  dst->runtime_accounts_capacity = src->runtime_accounts_count;
  dst->runtime_accounts_count = 0;

  for (size_t i = 0; i < src->runtime_accounts_count; ++i) {
    EVM_Status status = runtime_account_copy(&dst->runtime_accounts[i],
                                             &src->runtime_accounts[i]);
    if (status != EVM_OK) {
      dst->runtime_accounts_count = i + 1U;
      runtime_accounts_release(dst);
      return status;
    }
    dst->runtime_accounts_count = i + 1U;
  }

  return EVM_OK;
}

void runtime_accounts_commit_from_child(EVM_State *parent,
                                               EVM_State *child) {
  runtime_accounts_release(parent);
  parent->runtime_accounts = child->runtime_accounts;
  parent->runtime_accounts_count = child->runtime_accounts_count;
  parent->runtime_accounts_capacity = child->runtime_accounts_capacity;

  child->runtime_accounts = nullptr;
  child->runtime_accounts_count = 0;
  child->runtime_accounts_capacity = 0;
}

static EVM_Status frame_set_storage_entries(EVM_State *vm,
                                            const EVM_StorageEntry *storage,
                                            size_t storage_count) {
  EVM_StorageEntry *new_storage = nullptr;
  if (storage_count > 0U) {
    if (storage == nullptr) {
      return EVM_ERR_INTERNAL;
    }
    new_storage = calloc(storage_count, sizeof(EVM_StorageEntry));
    if (new_storage == nullptr) {
      return EVM_ERR_OOM;
    }
    memcpy(new_storage, storage, storage_count * sizeof(EVM_StorageEntry));
  }

  free(vm->storage);
  vm->storage = new_storage;
  vm->storage_count = storage_count;
  vm->storage_capacity = storage_count;
  return storage_index_rebuild(vm);
}

static EVM_Status frame_set_transient_entries(EVM_State *vm,
                                              const EVM_TransientEntry *entries,
                                              size_t entries_count) {
  EVM_TransientEntry *new_entries = nullptr;
  if (entries_count > 0U) {
    if (entries == nullptr) {
      return EVM_ERR_INTERNAL;
    }
    new_entries = calloc(entries_count, sizeof(EVM_TransientEntry));
    if (new_entries == nullptr) {
      return EVM_ERR_OOM;
    }
    memcpy(new_entries, entries, entries_count * sizeof(EVM_TransientEntry));
  }

  free(vm->transient_storage);
  vm->transient_storage = new_entries;
  vm->transient_storage_count = entries_count;
  vm->transient_storage_capacity = entries_count;
  return EVM_OK;
}

EVM_Status runtime_account_load_frame_state(EVM_State *vm,
                                                   const uint256_t *address) {
  EVM_RuntimeAccount account;
  // Frame-local storage/transient arrays are loaded from the account snapshot.
  if (!runtime_account_read(vm, address, &account)) {
    EVM_Status status = frame_set_storage_entries(vm, nullptr, 0U);
    if (status != EVM_OK) {
      return status;
    }
    return frame_set_transient_entries(vm, nullptr, 0U);
  }

  EVM_Status status =
      frame_set_storage_entries(vm, account.storage, account.storage_count);
  if (status != EVM_OK) {
    return status;
  }
  return frame_set_transient_entries(vm, account.transient_storage,
                                     account.transient_storage_count);
}

EVM_Status runtime_account_store_frame_state(EVM_State *vm,
                                                    const uint256_t *address) {
  EVM_RuntimeAccount *account = nullptr;
  EVM_Status status = runtime_account_ensure(vm, address, &account);
  if (status != EVM_OK) {
    return status;
  }

  // Persist the frame-local storage/transient view back to runtime account map.
  status = runtime_account_set_storage_entries(account, vm->storage,
                                               vm->storage_count);
  if (status != EVM_OK) {
    return status;
  }
  status = runtime_account_set_transient_entries(account, vm->transient_storage,
                                                 vm->transient_storage_count);
  if (status != EVM_OK) {
    return status;
  }

  if (vm->storage_count > 0U || vm->transient_storage_count > 0U) {
    account->destroyed = false;
  }
  return EVM_OK;
}

EVM_Status sync_current_account_runtime_state(EVM_State *vm) {
  EVM_RuntimeAccount *account = nullptr;
  EVM_Status status = runtime_account_ensure(vm, &vm->address, &account);
  if (status != EVM_OK) {
    return status;
  }

  // Flush current executing account before forking child frames.
  status = runtime_account_set_code(account, vm->code, vm->code_size);
  if (status != EVM_OK) {
    return status;
  }
  account->balance = vm->self_balance;
  account->code_hash = uint256_zero();

  return runtime_account_store_frame_state(vm, &vm->address);
}

EVM_Status sync_frame_from_current_account(EVM_State *vm) {
  EVM_Status status = runtime_account_load_frame_state(vm, &vm->address);
  if (status != EVM_OK) {
    return status;
  }

  EVM_RuntimeAccount account;
  if (runtime_account_read(vm, &vm->address, &account)) {
    vm->self_balance = account.balance;
  } else {
    vm->self_balance = uint256_zero();
  }
  return EVM_OK;
}

EVM_Status merge_child_logs(EVM_State *vm, const EVM_State *child) {
  if (child->logs_count == 0U) {
    return EVM_OK;
  }

  size_t original_count = vm->logs_count;
  for (size_t i = 0; i < child->logs_count; ++i) {
    if (vm->logs_count == vm->logs_capacity) {
      EVM_Status status =
          reserve_realloc_array((void **)&vm->logs, &vm->logs_capacity,
                                vm->logs_count + 1U, sizeof(EVM_LogEntry));
      if (status != EVM_OK) {
        goto oom;
      }
    }

    EVM_LogEntry entry;
    memset(&entry, 0, sizeof(entry));
    entry.topics_count = child->logs[i].topics_count;
    memcpy(entry.topics, child->logs[i].topics,
           child->logs[i].topics_count * sizeof(uint256_t));

    if (child->logs[i].data_size > 0U) {
      entry.data = calloc(child->logs[i].data_size, sizeof(uint8_t));
      if (entry.data == nullptr) {
        goto oom;
      }
      memcpy(entry.data, child->logs[i].data, child->logs[i].data_size);
      entry.data_size = child->logs[i].data_size;
    }

    vm->logs[vm->logs_count++] = entry;
  }

  return EVM_OK;

oom:
  for (size_t i = original_count; i < vm->logs_count; ++i) {
    free(vm->logs[i].data);
    vm->logs[i].data = nullptr;
  }
  vm->logs_count = original_count;
  return EVM_ERR_OOM;
}

uint256_t block_hash_lookup(const EVM_State *vm,
                                   const uint256_t *number) {
  for (size_t i = 0; i < vm->block_hashes_count; ++i) {
    if (uint256_cmp(&vm->block_hashes[i].number, number) == 0) {
      return vm->block_hashes[i].hash;
    }
  }
  return uint256_zero();
}

bool uint256_fits_u64(const uint256_t *value) {
  return value->limbs[1] == 0 && value->limbs[2] == 0 && value->limbs[3] == 0;
}

EVM_Status ensure_memory_range(EVM_State *vm, size_t offset,
                                      size_t size) {
  if (size == 0) {
    return EVM_OK;
  }
  size_t end = 0;
  if (add_size_overflow(offset, size, &end)) {
    return EVM_ERR_RUNTIME;
  }
  return evm_memory_ensure(vm, end);
}

void rollback_logs(EVM_State *vm, size_t logs_start_count) {
  for (size_t i = logs_start_count; i < vm->logs_count; ++i) {
    free(vm->logs[i].data);
    vm->logs[i].data = nullptr;
    vm->logs[i].data_size = 0;
    vm->logs[i].topics_count = 0;
  }
  vm->logs_count = logs_start_count;
}
