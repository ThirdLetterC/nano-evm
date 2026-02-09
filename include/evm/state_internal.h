#ifndef EVM_STATE_INTERNAL_H
#define EVM_STATE_INTERNAL_H

#include "evm/common_internal.h"

uint256_t storage_get(const EVM_State *vm, const uint256_t *key);
EVM_Status storage_set(EVM_State *vm, const uint256_t *key,
                       const uint256_t *value, const uint256_t *original,
                       bool existed_at_start, const uint256_t *tx_original,
                       bool existed_at_transaction_start);
void storage_snapshot_originals(EVM_State *vm);
void storage_snapshot_transaction_originals(EVM_State *vm);
void storage_rollback(EVM_State *vm);

EVM_Status warm_slot_mark(EVM_State *vm, const uint256_t *address,
                          const uint256_t *key, bool *was_warm);
EVM_Status warm_slots_clone(EVM_State *dst, const EVM_State *src);
void warm_slots_commit_from_child(EVM_State *parent, EVM_State *child);

EVM_Status warm_account_mark(EVM_State *vm, const uint256_t *address,
                             bool *was_warm);
EVM_Status warm_accounts_clone(EVM_State *dst, const EVM_State *src);
void warm_accounts_commit_from_child(EVM_State *parent, EVM_State *child);

uint256_t transient_storage_get(const EVM_State *vm, const uint256_t *key);
EVM_Status transient_storage_set(EVM_State *vm, const uint256_t *key,
                                 const uint256_t *value);

EVM_Status runtime_account_ensure(EVM_State *vm, const uint256_t *address,
                                  EVM_RuntimeAccount **out_account);
bool runtime_account_read(const EVM_State *vm, const uint256_t *address,
                          EVM_RuntimeAccount *out_account);

uint256_t account_balance_get(const EVM_State *vm, const uint256_t *address);
bool account_code_get(const EVM_State *vm, const uint256_t *address,
                      const uint8_t **out_code, size_t *out_code_size,
                      uint256_t *out_balance);
uint256_t account_code_hash_get(const EVM_State *vm, const uint256_t *address);
EVM_Status account_credit(EVM_State *vm, const uint256_t *address,
                          const uint256_t *amount);
EVM_Status account_transfer(EVM_State *vm, const uint256_t *from,
                            const uint256_t *to, const uint256_t *amount);
EVM_Status account_deploy_contract(EVM_State *vm, const uint256_t *address,
                                   const uint8_t *runtime_code,
                                   size_t runtime_code_size,
                                   const uint256_t *balance);
EVM_Status account_nonce_get(EVM_State *vm, const uint256_t *address,
                             uint256_t *out_nonce);
EVM_Status account_nonce_increment(EVM_State *vm, const uint256_t *address);
bool runtime_account_code_is_empty(const EVM_RuntimeAccount *account);
bool account_is_dead(const EVM_State *vm, const uint256_t *address);
EVM_Status account_mark_selfdestruct(EVM_State *vm, const uint256_t *address);
EVM_Status account_mark_destroyed(EVM_State *vm, const uint256_t *address);
EVM_Status runtime_accounts_apply_selfdestructs(EVM_State *vm);

void runtime_accounts_release(EVM_State *vm);
void runtime_accounts_snapshot_transaction_originals(EVM_State *vm);
EVM_Status runtime_accounts_clone(EVM_State *dst, const EVM_State *src);
void runtime_accounts_commit_from_child(EVM_State *parent, EVM_State *child);

EVM_Status runtime_account_load_frame_state(EVM_State *vm,
                                            const uint256_t *address);
EVM_Status runtime_account_store_frame_state(EVM_State *vm,
                                             const uint256_t *address);
EVM_Status sync_current_account_runtime_state(EVM_State *vm);
EVM_Status sync_frame_from_current_account(EVM_State *vm);

EVM_Status merge_child_logs(EVM_State *vm, const EVM_State *child);
uint256_t block_hash_lookup(const EVM_State *vm, const uint256_t *number);
bool uint256_fits_u64(const uint256_t *value);
EVM_Status ensure_memory_range(EVM_State *vm, size_t offset, size_t size);
void rollback_logs(EVM_State *vm, size_t logs_start_count);

#endif
