#pragma once

#include <stddef.h>
#include <stdint.h>

#include "stack.h"

typedef enum {
  EVM_OK = 0,
  EVM_ERR_STACK_OVERFLOW,
  EVM_ERR_STACK_UNDERFLOW,
  EVM_ERR_INVALID_OPCODE,
  EVM_ERR_INVALID_BYTECODE,
  EVM_ERR_OUT_OF_GAS,
  EVM_ERR_WRITE_PROTECTION,
  EVM_ERR_REVERT,
  EVM_ERR_HEX_PARSE,
  EVM_ERR_RUNTIME,
  EVM_ERR_INTERNAL,
  EVM_ERR_OOM
} EVM_Status;

typedef struct {
  uint256_t key;
  uint256_t value;
  uint256_t original;
  bool existed_at_start;
  uint256_t tx_original;
  bool existed_at_transaction_start;
} EVM_StorageEntry;

typedef struct {
  uint256_t topics[4];
  size_t topics_count;
  uint8_t *data;
  size_t data_size;
} EVM_LogEntry;

typedef struct {
  uint256_t address;
  uint256_t key;
} EVM_AccessEntry;

typedef struct {
  uint256_t key;
  uint256_t value;
} EVM_TransientEntry;

typedef struct {
  uint256_t address;
  uint256_t balance;
  const uint8_t *code;
  size_t code_size;
  uint256_t code_hash;
  uint256_t nonce;
} EVM_ExternalAccount;

typedef struct {
  uint256_t number;
  uint256_t hash;
} EVM_BlockHashEntry;

typedef struct {
  uint256_t address;
  uint256_t balance;
  const uint8_t *code;
  size_t code_size;
  uint256_t code_hash;
  uint256_t nonce;
  EVM_StorageEntry *storage;
  size_t storage_count;
  size_t storage_capacity;
  EVM_TransientEntry *transient_storage;
  size_t transient_storage_count;
  size_t transient_storage_capacity;
  bool code_owned;
  bool destroyed;
  bool selfdestruct_pending;
  bool created_in_transaction;
} EVM_RuntimeAccount;

typedef struct {
  size_t pc;
  uint64_t gas_limit;
  uint64_t gas_remaining;
  int64_t refund_counter;
  EVM_Stack stack;
  uint8_t *memory;
  size_t memory_size;
  const uint8_t *call_data;
  size_t call_data_size;
  uint8_t *return_data;
  size_t return_data_size;
  EVM_StorageEntry *storage;
  size_t storage_count;
  size_t storage_capacity;
  size_t *storage_index_table;
  size_t storage_index_table_capacity;
  EVM_TransientEntry *transient_storage;
  size_t transient_storage_count;
  size_t transient_storage_capacity;
  uint256_t *warm_accounts;
  size_t warm_accounts_count;
  size_t warm_accounts_capacity;
  size_t *warm_accounts_index_table;
  size_t warm_accounts_index_table_capacity;
  EVM_AccessEntry *warm_slots;
  size_t warm_slots_count;
  size_t warm_slots_capacity;
  size_t *warm_slots_index_table;
  size_t warm_slots_index_table_capacity;
  EVM_LogEntry *logs;
  size_t logs_count;
  size_t logs_capacity;
  uint256_t address;
  uint256_t self_balance;
  uint256_t origin;
  uint256_t caller;
  uint256_t call_value;
  size_t call_depth;
  uint256_t gas_price;
  uint256_t coinbase;
  uint256_t timestamp;
  uint256_t block_number;
  uint256_t prev_randao;
  uint256_t block_gas_limit;
  uint256_t chain_id;
  uint256_t base_fee;
  uint256_t blob_base_fee;
  const uint256_t *blob_hashes;
  size_t blob_hashes_count;
  const EVM_ExternalAccount *external_accounts;
  size_t external_accounts_count;
  const EVM_BlockHashEntry *block_hashes;
  size_t block_hashes_count;
  EVM_RuntimeAccount *runtime_accounts;
  size_t runtime_accounts_count;
  size_t runtime_accounts_capacity;
  bool is_static_context;
  const uint8_t *code;
  size_t code_size;
  uint8_t *jumpdest_bitmap;
  size_t jumpdest_bitmap_size;
} EVM_State;

[[nodiscard]] EVM_Status evm_init(EVM_State *vm, const uint8_t *code,
                                  size_t code_size, uint64_t gas_limit);
void evm_destroy(EVM_State *vm);

[[nodiscard]] EVM_Status evm_execute(EVM_State *vm);
[[nodiscard]] EVM_Status evm_load_hex(const char *hex, uint8_t **out_code,
                                      size_t *out_size);
[[nodiscard]] EVM_Status evm_memory_ensure(EVM_State *vm, size_t required_size);

[[nodiscard]] const char *evm_status_string(EVM_Status status);
