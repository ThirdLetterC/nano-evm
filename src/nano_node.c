#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#if defined(__has_include)
#if __has_include(<stdckdint.h>)
#include <stdckdint.h>
#define NANO_NODE_HAVE_STDCKDINT 1
#endif
#endif

#ifndef NANO_NODE_HAVE_STDCKDINT
#define NANO_NODE_HAVE_STDCKDINT 0
#endif

#include "evm.h"
#include "nano_utils.h"
#include "nanosol.h"
#include "stack.h"
#include "uint256.h"

typedef struct {
  uint8_t *code;
  size_t code_size;
  EVM_StorageEntry *storage;
  size_t storage_count;
  EVM_TransientEntry *transient_storage;
  size_t transient_storage_count;
  EVM_RuntimeAccount *runtime_accounts;
  size_t runtime_accounts_count;
  uint256_t self_balance;
  uint256_t contract_address;
} NodeState;

static constexpr uint8_t NODE_MAGIC[8] = {'N', 'N', 'O', 'D',
                                          'E', '0', '0', '1'};
static constexpr uint32_t NODE_STATE_VERSION = 3U;
static constexpr uint32_t NODE_STATE_VERSION_U64_RUNTIME_NONCE = 2U;
static constexpr uint32_t NODE_STATE_VERSION_STORAGE_ONLY = 1U;
static constexpr uint64_t DEFAULT_GAS_LIMIT = 3'000'000U;
static constexpr uint64_t DEFAULT_CALLER = 1U;
static constexpr uint64_t DEFAULT_CONTRACT_ADDRESS = 0x100U;
static constexpr size_t NODE_STATE_MAX_FILE_BYTES = 256U * 1'024U * 1'024U;
static constexpr size_t NODE_STATE_MAX_CODE_SIZE = 24'576U;
static constexpr size_t NODE_STATE_MAX_STORAGE_ENTRIES = 1'000'000U;
static constexpr size_t NODE_STATE_MAX_TRANSIENT_ENTRIES = 1'000'000U;
static constexpr size_t NODE_STATE_MAX_RUNTIME_ACCOUNTS = 200'000U;
static constexpr uint8_t NODE_RUNTIME_ACCOUNT_FLAG_DESTROYED = 0x01U;
static constexpr uint8_t NODE_RUNTIME_ACCOUNT_FLAGS_ALLOWED =
    NODE_RUNTIME_ACCOUNT_FLAG_DESTROYED;

static bool checked_add_size(size_t a, size_t b, size_t *out) {
  if (out == nullptr) {
    return false;
  }
#if NANO_NODE_HAVE_STDCKDINT
  return !ckd_add(out, a, b);
#else
  if (a > (SIZE_MAX - b)) {
    return false;
  }
  *out = a + b;
  return true;
#endif
}

static bool checked_mul_size(size_t a, size_t b, size_t *out) {
  if (out == nullptr) {
    return false;
  }
#if NANO_NODE_HAVE_STDCKDINT
  return !ckd_mul(out, a, b);
#else
  if (a != 0U && b > (SIZE_MAX / a)) {
    return false;
  }
  *out = a * b;
  return true;
#endif
}

static void print_usage(const char *prog) {
  fprintf(
      stderr,
      "Usage:\n"
      "  %s deploy --state <file> (--source <file.nsol> | --bytecode <hex>) "
      "[--address <word>]\n"
      "  %s call --state <file> [--calldata <hex> | --cmd <word> [--argN "
      "<word>]...] [--caller <word>] [--value <word>] "
      "[--gas <limit>]\n"
      "  %s inspect --state <file>\n"
      "  %s reset --state <file>\n",
      prog, prog, prog, prog);
}

static void node_state_init(NodeState *state) {
  state->code = nullptr;
  state->code_size = 0;
  state->storage = nullptr;
  state->storage_count = 0;
  state->transient_storage = nullptr;
  state->transient_storage_count = 0;
  state->runtime_accounts = nullptr;
  state->runtime_accounts_count = 0;
  state->self_balance = uint256_zero();
  state->contract_address = uint256_from_u64(DEFAULT_CONTRACT_ADDRESS);
}

static void runtime_account_reset(EVM_RuntimeAccount *account) {
  if (account == nullptr) {
    return;
  }

  if (account->code_owned) {
    free((void *)account->code);
  }
  free(account->storage);
  free(account->transient_storage);

  memset(account, 0, sizeof(*account));
}

static void runtime_accounts_reset(EVM_RuntimeAccount *accounts, size_t count) {
  if (accounts == nullptr) {
    return;
  }
  for (size_t i = 0; i < count; ++i) {
    runtime_account_reset(&accounts[i]);
  }
  free(accounts);
}

static void node_state_destroy(NodeState *state) {
  free(state->code);
  state->code = nullptr;
  state->code_size = 0;
  free(state->storage);
  state->storage = nullptr;
  state->storage_count = 0;
  free(state->transient_storage);
  state->transient_storage = nullptr;
  state->transient_storage_count = 0;
  runtime_accounts_reset(state->runtime_accounts,
                         state->runtime_accounts_count);
  state->runtime_accounts = nullptr;
  state->runtime_accounts_count = 0;
  state->self_balance = uint256_zero();
  state->contract_address = uint256_zero();
}

static bool write_all(FILE *file, const void *data, size_t size) {
  if (file == nullptr || (size > 0U && data == nullptr)) {
    return false;
  }
  const uint8_t *cursor = data;
  size_t remaining = size;
  while (remaining > 0U) {
    size_t wrote = fwrite(cursor, sizeof(uint8_t), remaining, file);
    if (wrote == 0U) {
      return false;
    }
    cursor += wrote;
    remaining -= wrote;
  }
  return true;
}

static bool read_exact(FILE *file, void *out_data, size_t size) {
  if (file == nullptr || (size > 0U && out_data == nullptr)) {
    return false;
  }
  uint8_t *cursor = out_data;
  size_t remaining = size;
  while (remaining > 0U) {
    size_t got = fread(cursor, sizeof(uint8_t), remaining, file);
    if (got == 0U) {
      return false;
    }
    cursor += got;
    remaining -= got;
  }
  return true;
}

static bool write_u32_le(FILE *file, uint32_t value) {
  uint8_t bytes[4] = {
      (uint8_t)(value & 0xffU),
      (uint8_t)((value >> 8U) & 0xffU),
      (uint8_t)((value >> 16U) & 0xffU),
      (uint8_t)((value >> 24U) & 0xffU),
  };
  return write_all(file, bytes, sizeof(bytes));
}

static bool write_u64_le(FILE *file, uint64_t value) {
  uint8_t bytes[8] = {
      (uint8_t)(value & 0xffU),          (uint8_t)((value >> 8U) & 0xffU),
      (uint8_t)((value >> 16U) & 0xffU), (uint8_t)((value >> 24U) & 0xffU),
      (uint8_t)((value >> 32U) & 0xffU), (uint8_t)((value >> 40U) & 0xffU),
      (uint8_t)((value >> 48U) & 0xffU), (uint8_t)((value >> 56U) & 0xffU),
  };
  return write_all(file, bytes, sizeof(bytes));
}

static bool read_u32_le(FILE *file, uint32_t *out_value) {
  if (out_value == nullptr) {
    return false;
  }
  uint8_t bytes[4];
  if (!read_exact(file, bytes, sizeof(bytes))) {
    return false;
  }
  *out_value = (uint32_t)bytes[0] | ((uint32_t)bytes[1] << 8U) |
               ((uint32_t)bytes[2] << 16U) | ((uint32_t)bytes[3] << 24U);
  return true;
}

static bool read_u64_le(FILE *file, uint64_t *out_value) {
  if (out_value == nullptr) {
    return false;
  }
  uint8_t bytes[8];
  if (!read_exact(file, bytes, sizeof(bytes))) {
    return false;
  }
  *out_value = (uint64_t)bytes[0] | ((uint64_t)bytes[1] << 8U) |
               ((uint64_t)bytes[2] << 16U) | ((uint64_t)bytes[3] << 24U) |
               ((uint64_t)bytes[4] << 32U) | ((uint64_t)bytes[5] << 40U) |
               ((uint64_t)bytes[6] << 48U) | ((uint64_t)bytes[7] << 56U);
  return true;
}

static bool write_u8(FILE *file, uint8_t value) {
  return write_all(file, &value, sizeof(value));
}

static bool read_u8(FILE *file, uint8_t *out_value) {
  if (out_value == nullptr) {
    return false;
  }
  return read_exact(file, out_value, sizeof(*out_value));
}

static bool write_uint256(FILE *file, const uint256_t *value) {
  uint8_t bytes[32];
  uint256_to_be_bytes(value, bytes);
  return write_all(file, bytes, sizeof(bytes));
}

static bool read_uint256(FILE *file, uint256_t *out_value) {
  if (out_value == nullptr) {
    return false;
  }
  uint8_t bytes[32];
  if (!read_exact(file, bytes, sizeof(bytes))) {
    return false;
  }
  uint256_from_be_bytes(out_value, bytes);
  return true;
}

static void normalize_storage_entries(EVM_StorageEntry *entries, size_t count) {
  for (size_t i = 0; i < count; ++i) {
    entries[i].original = entries[i].value;
    entries[i].existed_at_start = true;
    entries[i].tx_original = entries[i].value;
    entries[i].existed_at_transaction_start = true;
  }
}

static bool write_storage_entries(FILE *file, const EVM_StorageEntry *entries,
                                  size_t count) {
  for (size_t i = 0; i < count; ++i) {
    if (!write_uint256(file, &entries[i].key) ||
        !write_uint256(file, &entries[i].value)) {
      return false;
    }
  }
  return true;
}

static bool read_storage_entries(FILE *file, EVM_StorageEntry *entries,
                                 size_t count) {
  if (count > 0U && entries == nullptr) {
    return false;
  }
  for (size_t i = 0; i < count; ++i) {
    if (!read_uint256(file, &entries[i].key) ||
        !read_uint256(file, &entries[i].value)) {
      return false;
    }
  }
  normalize_storage_entries(entries, count);
  return true;
}

static bool write_transient_entries(FILE *file,
                                    const EVM_TransientEntry *entries,
                                    size_t count) {
  for (size_t i = 0; i < count; ++i) {
    if (!write_uint256(file, &entries[i].key) ||
        !write_uint256(file, &entries[i].value)) {
      return false;
    }
  }
  return true;
}

static bool read_transient_entries(FILE *file, EVM_TransientEntry *entries,
                                   size_t count) {
  if (count > 0U && entries == nullptr) {
    return false;
  }
  for (size_t i = 0; i < count; ++i) {
    if (!read_uint256(file, &entries[i].key) ||
        !read_uint256(file, &entries[i].value)) {
      return false;
    }
  }
  return true;
}

static bool write_runtime_account(FILE *file,
                                  const EVM_RuntimeAccount *account) {
  if ((account->code_size > 0U && account->code == nullptr) ||
      (account->storage_count > 0U && account->storage == nullptr) ||
      (account->transient_storage_count > 0U &&
       account->transient_storage == nullptr)) {
    return false;
  }

  if (account->code_size > UINT64_MAX || account->storage_count > UINT64_MAX ||
      account->transient_storage_count > UINT64_MAX) {
    return false;
  }

  uint8_t flags = 0U;
  if (account->destroyed) {
    flags |= NODE_RUNTIME_ACCOUNT_FLAG_DESTROYED;
  }

  if (!write_uint256(file, &account->address) ||
      !write_uint256(file, &account->balance) ||
      !write_uint256(file, &account->code_hash) ||
      !write_uint256(file, &account->nonce) || !write_u8(file, flags) ||
      !write_u64_le(file, (uint64_t)account->code_size) ||
      !write_u64_le(file, (uint64_t)account->storage_count) ||
      !write_u64_le(file, (uint64_t)account->transient_storage_count)) {
    return false;
  }

  if (!write_all(file, account->code, account->code_size) ||
      !write_storage_entries(file, account->storage, account->storage_count) ||
      !write_transient_entries(file, account->transient_storage,
                               account->transient_storage_count)) {
    return false;
  }
  return true;
}

static bool read_runtime_account(FILE *file, EVM_RuntimeAccount *account,
                                 bool nonce_encoded_as_u64) {
  if (account == nullptr) {
    return false;
  }
  uint64_t code_size_u64 = 0;
  uint64_t storage_count_u64 = 0;
  uint64_t transient_count_u64 = 0;
  uint64_t nonce_u64 = 0;
  uint8_t flags = 0U;

  if (!read_uint256(file, &account->address) ||
      !read_uint256(file, &account->balance) ||
      !read_uint256(file, &account->code_hash)) {
    return false;
  }
  if (nonce_encoded_as_u64) {
    if (!read_u64_le(file, &nonce_u64)) {
      return false;
    }
    account->nonce = uint256_from_u64(nonce_u64);
  } else if (!read_uint256(file, &account->nonce)) {
    return false;
  }
  if (!read_u8(file, &flags) || !read_u64_le(file, &code_size_u64) ||
      !read_u64_le(file, &storage_count_u64) ||
      !read_u64_le(file, &transient_count_u64)) {
    return false;
  }
  if ((flags & (uint8_t)~NODE_RUNTIME_ACCOUNT_FLAGS_ALLOWED) != 0U) {
    return false;
  }

#if SIZE_MAX < UINT64_MAX
  if (code_size_u64 > SIZE_MAX || storage_count_u64 > SIZE_MAX ||
      transient_count_u64 > SIZE_MAX) {
    return false;
  }
#endif
  size_t code_size = (size_t)code_size_u64;
  size_t storage_count = (size_t)storage_count_u64;
  size_t transient_count = (size_t)transient_count_u64;
  if (code_size > NODE_STATE_MAX_CODE_SIZE ||
      storage_count > NODE_STATE_MAX_STORAGE_ENTRIES ||
      transient_count > NODE_STATE_MAX_TRANSIENT_ENTRIES) {
    return false;
  }
  if ((storage_count > 0U &&
       storage_count > SIZE_MAX / sizeof(EVM_StorageEntry)) ||
      (transient_count > 0U &&
       transient_count > SIZE_MAX / sizeof(EVM_TransientEntry))) {
    return false;
  }

  account->code = nullptr;
  account->code_size = 0;
  account->storage = nullptr;
  account->storage_count = 0;
  account->storage_capacity = 0;
  account->transient_storage = nullptr;
  account->transient_storage_count = 0;
  account->transient_storage_capacity = 0;
  account->code_owned = false;
  account->destroyed = ((flags & NODE_RUNTIME_ACCOUNT_FLAG_DESTROYED) != 0U);
  account->created_in_transaction = false;

  if (code_size > 0U) {
    uint8_t *code = calloc(code_size, sizeof(uint8_t));
    if (code == nullptr) {
      return false;
    }
    if (!read_exact(file, code, code_size)) {
      free(code);
      return false;
    }
    account->code = code;
    account->code_size = code_size;
    account->code_owned = true;
  }

  if (storage_count > 0U) {
    EVM_StorageEntry *storage = calloc(storage_count, sizeof(EVM_StorageEntry));
    if (storage == nullptr) {
      runtime_account_reset(account);
      return false;
    }
    if (!read_storage_entries(file, storage, storage_count)) {
      free(storage);
      runtime_account_reset(account);
      return false;
    }
    account->storage = storage;
    account->storage_count = storage_count;
    account->storage_capacity = storage_count;
  }

  if (transient_count > 0U) {
    EVM_TransientEntry *transient =
        calloc(transient_count, sizeof(EVM_TransientEntry));
    if (transient == nullptr) {
      runtime_account_reset(account);
      return false;
    }
    if (!read_transient_entries(file, transient, transient_count)) {
      free(transient);
      runtime_account_reset(account);
      return false;
    }
    account->transient_storage = transient;
    account->transient_storage_count = transient_count;
    account->transient_storage_capacity = transient_count;
  }

  return true;
}

static bool write_runtime_accounts(FILE *file,
                                   const EVM_RuntimeAccount *accounts,
                                   size_t count) {
  for (size_t i = 0; i < count; ++i) {
    if (!write_runtime_account(file, &accounts[i])) {
      return false;
    }
  }
  return true;
}

static bool read_runtime_accounts(FILE *file, EVM_RuntimeAccount *accounts,
                                  size_t count, bool nonce_encoded_as_u64) {
  if (count > 0U && accounts == nullptr) {
    return false;
  }
  for (size_t i = 0; i < count; ++i) {
    if (!read_runtime_account(file, &accounts[i], nonce_encoded_as_u64)) {
      return false;
    }
  }
  return true;
}

static bool node_state_save(const char *path, const NodeState *state) {
  static constexpr char temp_suffix[] = ".tmp";

  size_t path_len = strlen(path);
  size_t temp_path_len = 0U;
  if (!checked_add_size(path_len, sizeof(temp_suffix), &temp_path_len)) {
    fprintf(stderr, "State file path too long: %s\n", path);
    return false;
  }

  char *temp_path = calloc(temp_path_len, sizeof(char));
  if (temp_path == nullptr) {
    fprintf(stderr, "Out of memory while creating temp state path\n");
    return false;
  }
  memcpy(temp_path, path, path_len);
  memcpy(temp_path + path_len, temp_suffix, sizeof(temp_suffix));

  FILE *file = fopen(temp_path, "wb");
  if (file == nullptr) {
    fprintf(stderr, "Failed to open temp state file for write: %s\n",
            temp_path);
    free(temp_path);
    return false;
  }

  bool ok = true;
  if ((state->code_size > 0U && state->code == nullptr) ||
      (state->storage_count > 0U && state->storage == nullptr) ||
      (state->transient_storage_count > 0U &&
       state->transient_storage == nullptr) ||
      (state->runtime_accounts_count > 0U &&
       state->runtime_accounts == nullptr)) {
    ok = false;
  }
  if (state->code_size > UINT64_MAX || state->storage_count > UINT64_MAX ||
      state->transient_storage_count > UINT64_MAX ||
      state->runtime_accounts_count > UINT64_MAX) {
    ok = false;
  }
  for (size_t i = 0; ok && i < state->runtime_accounts_count; ++i) {
    if (state->runtime_accounts[i].code_size > UINT64_MAX ||
        state->runtime_accounts[i].storage_count > UINT64_MAX ||
        state->runtime_accounts[i].transient_storage_count > UINT64_MAX) {
      ok = false;
      break;
    }
  }

  ok = ok && write_all(file, NODE_MAGIC, sizeof(NODE_MAGIC));
  ok = ok && write_u32_le(file, NODE_STATE_VERSION);
  ok = ok && write_u32_le(file, 0U);
  ok = ok && write_uint256(file, &state->contract_address);
  ok = ok && write_uint256(file, &state->self_balance);
  ok = ok && write_u64_le(file, (uint64_t)state->code_size);
  ok = ok && write_u64_le(file, (uint64_t)state->storage_count);
  ok = ok && write_u64_le(file, (uint64_t)state->transient_storage_count);
  ok = ok && write_u64_le(file, (uint64_t)state->runtime_accounts_count);
  ok = ok && write_all(file, state->code, state->code_size);
  ok = ok && write_storage_entries(file, state->storage, state->storage_count);
  ok = ok && write_transient_entries(file, state->transient_storage,
                                     state->transient_storage_count);
  ok = ok && write_runtime_accounts(file, state->runtime_accounts,
                                    state->runtime_accounts_count);

  if (!ok) {
    fprintf(stderr, "Failed to write temp state file: %s\n", temp_path);
  }

  if (ok) {
    if (fflush(file) != 0) {
      fprintf(stderr, "Failed to flush temp state file: %s\n", temp_path);
      ok = false;
    } else if (fsync(fileno(file)) != 0) {
      fprintf(stderr, "Failed to sync temp state file: %s\n", temp_path);
      ok = false;
    }
  }

  if (fclose(file) != 0) {
    if (ok) {
      fprintf(stderr, "Failed to close temp state file: %s\n", temp_path);
    }
    ok = false;
  }

  if (ok && rename(temp_path, path) != 0) {
    fprintf(stderr, "Failed to replace state file: %s\n", path);
    ok = false;
  }

  if (!ok) {
    (void)remove(temp_path);
  }

  free(temp_path);
  return ok;
}

static bool node_state_load(const char *path, NodeState *out_state) {
  if (path == nullptr || out_state == nullptr) {
    fprintf(stderr, "Invalid state load arguments\n");
    return false;
  }
  node_state_init(out_state);

  FILE *file = fopen(path, "rb");
  if (file == nullptr) {
    fprintf(stderr, "Failed to open state file: %s\n", path);
    return false;
  }
  if (fseek(file, 0, SEEK_END) != 0) {
    fprintf(stderr, "Failed to stat state file: %s\n", path);
    fclose(file);
    return false;
  }
  long end = ftell(file);
  if (end < 0) {
    fprintf(stderr, "Failed to stat state file: %s\n", path);
    fclose(file);
    return false;
  }
  if ((uintmax_t)end > (uintmax_t)NODE_STATE_MAX_FILE_BYTES) {
    fprintf(stderr, "State file exceeds maximum size (%zu bytes): %s\n",
            NODE_STATE_MAX_FILE_BYTES, path);
    fclose(file);
    return false;
  }
  if (fseek(file, 0, SEEK_SET) != 0) {
    fprintf(stderr, "Failed to read state file: %s\n", path);
    fclose(file);
    return false;
  }

  uint8_t magic[8] = {0};
  uint32_t version = 0;
  uint32_t reserved = 0;
  uint64_t code_size_u64 = 0;
  uint64_t storage_count_u64 = 0;
  uint64_t transient_count_u64 = 0;
  uint64_t runtime_accounts_count_u64 = 0;
  bool ok = true;

  ok = ok && read_exact(file, magic, sizeof(magic));
  ok = ok && read_u32_le(file, &version);
  ok = ok && read_u32_le(file, &reserved);
  if (!ok) {
    fprintf(stderr, "State file is truncated or unreadable: %s\n", path);
    fclose(file);
    return false;
  }

  if (memcmp(magic, NODE_MAGIC, sizeof(magic)) != 0) {
    fprintf(stderr, "State file magic mismatch: %s\n", path);
    fclose(file);
    return false;
  }
  if (version != NODE_STATE_VERSION &&
      version != NODE_STATE_VERSION_U64_RUNTIME_NONCE &&
      version != NODE_STATE_VERSION_STORAGE_ONLY) {
    fprintf(stderr, "Unsupported state version (%" PRIu32 "): %s\n", version,
            path);
    fclose(file);
    return false;
  }
  if (reserved != 0U) {
    fprintf(stderr, "Unsupported state header flags (0x%08" PRIx32 "): %s\n",
            reserved, path);
    fclose(file);
    return false;
  }

  ok = ok && read_uint256(file, &out_state->contract_address);
  if (version == NODE_STATE_VERSION ||
      version == NODE_STATE_VERSION_U64_RUNTIME_NONCE) {
    ok = ok && read_uint256(file, &out_state->self_balance);
    ok = ok && read_u64_le(file, &code_size_u64);
    ok = ok && read_u64_le(file, &storage_count_u64);
    ok = ok && read_u64_le(file, &transient_count_u64);
    ok = ok && read_u64_le(file, &runtime_accounts_count_u64);
  } else {
    out_state->self_balance = uint256_zero();
    ok = ok && read_u64_le(file, &code_size_u64);
    ok = ok && read_u64_le(file, &storage_count_u64);
    transient_count_u64 = 0U;
    runtime_accounts_count_u64 = 0U;
  }
  if (!ok) {
    fprintf(stderr, "State file is truncated or unreadable: %s\n", path);
    fclose(file);
    return false;
  }

#if SIZE_MAX < UINT64_MAX
  if (code_size_u64 > SIZE_MAX || storage_count_u64 > SIZE_MAX ||
      transient_count_u64 > SIZE_MAX || runtime_accounts_count_u64 > SIZE_MAX) {
    fprintf(stderr, "State file too large for this platform: %s\n", path);
    fclose(file);
    return false;
  }
#endif
  size_t code_size = (size_t)code_size_u64;
  size_t storage_count = (size_t)storage_count_u64;
  size_t transient_count = (size_t)transient_count_u64;
  size_t runtime_accounts_count = (size_t)runtime_accounts_count_u64;
  if (code_size > NODE_STATE_MAX_CODE_SIZE) {
    fprintf(stderr, "Contract bytecode too large (%zu > %zu): %s\n", code_size,
            NODE_STATE_MAX_CODE_SIZE, path);
    fclose(file);
    return false;
  }
  if (storage_count > NODE_STATE_MAX_STORAGE_ENTRIES) {
    fprintf(stderr, "Storage entry count exceeds limit (%zu > %zu): %s\n",
            storage_count, NODE_STATE_MAX_STORAGE_ENTRIES, path);
    fclose(file);
    return false;
  }
  if (transient_count > NODE_STATE_MAX_TRANSIENT_ENTRIES) {
    fprintf(stderr,
            "Transient storage entry count exceeds limit (%zu > %zu): "
            "%s\n",
            transient_count, NODE_STATE_MAX_TRANSIENT_ENTRIES, path);
    fclose(file);
    return false;
  }
  if (runtime_accounts_count > NODE_STATE_MAX_RUNTIME_ACCOUNTS) {
    fprintf(stderr, "Runtime account count exceeds limit (%zu > %zu): %s\n",
            runtime_accounts_count, NODE_STATE_MAX_RUNTIME_ACCOUNTS, path);
    fclose(file);
    return false;
  }
  if (storage_count > 0U &&
      storage_count > SIZE_MAX / sizeof(EVM_StorageEntry)) {
    fprintf(stderr, "Storage table too large: %s\n", path);
    fclose(file);
    return false;
  }
  if (transient_count > 0U &&
      transient_count > SIZE_MAX / sizeof(EVM_TransientEntry)) {
    fprintf(stderr, "Transient storage table too large: %s\n", path);
    fclose(file);
    return false;
  }
  if (runtime_accounts_count > 0U &&
      runtime_accounts_count > SIZE_MAX / sizeof(EVM_RuntimeAccount)) {
    fprintf(stderr, "Runtime account table too large: %s\n", path);
    fclose(file);
    return false;
  }

  out_state->code = calloc(code_size, sizeof(uint8_t));
  if (out_state->code == nullptr && code_size > 0U) {
    fprintf(stderr, "Out of memory while loading code\n");
    fclose(file);
    node_state_destroy(out_state);
    return false;
  }
  out_state->code_size = code_size;
  out_state->storage = calloc(storage_count, sizeof(EVM_StorageEntry));
  if (out_state->storage == nullptr && storage_count > 0U) {
    fprintf(stderr, "Out of memory while loading storage\n");
    fclose(file);
    node_state_destroy(out_state);
    return false;
  }
  out_state->storage_count = storage_count;
  out_state->transient_storage =
      calloc(transient_count, sizeof(EVM_TransientEntry));
  if (out_state->transient_storage == nullptr && transient_count > 0U) {
    fprintf(stderr, "Out of memory while loading transient storage\n");
    fclose(file);
    node_state_destroy(out_state);
    return false;
  }
  out_state->transient_storage_count = transient_count;
  out_state->runtime_accounts =
      calloc(runtime_accounts_count, sizeof(EVM_RuntimeAccount));
  if (out_state->runtime_accounts == nullptr && runtime_accounts_count > 0U) {
    fprintf(stderr, "Out of memory while loading runtime accounts\n");
    fclose(file);
    node_state_destroy(out_state);
    return false;
  }
  out_state->runtime_accounts_count = runtime_accounts_count;

  if (!read_exact(file, out_state->code, out_state->code_size)) {
    fprintf(stderr, "Failed to read contract bytecode: %s\n", path);
    fclose(file);
    node_state_destroy(out_state);
    return false;
  }

  if (!read_storage_entries(file, out_state->storage,
                            out_state->storage_count)) {
    fprintf(stderr, "Failed to read storage entries: %s\n", path);
    fclose(file);
    node_state_destroy(out_state);
    return false;
  }
  if (!read_transient_entries(file, out_state->transient_storage,
                              out_state->transient_storage_count)) {
    fprintf(stderr, "Failed to read transient storage entries: %s\n", path);
    fclose(file);
    node_state_destroy(out_state);
    return false;
  }
  if (!read_runtime_accounts(file, out_state->runtime_accounts,
                             out_state->runtime_accounts_count,
                             version == NODE_STATE_VERSION_U64_RUNTIME_NONCE)) {
    fprintf(stderr, "Failed to read runtime accounts: %s\n", path);
    fclose(file);
    node_state_destroy(out_state);
    return false;
  }

  if (fgetc(file) != EOF) {
    fprintf(stderr, "State file contains trailing bytes: %s\n", path);
    fclose(file);
    node_state_destroy(out_state);
    return false;
  }
  if (ferror(file) != 0) {
    fprintf(stderr, "Failed while checking state file end: %s\n", path);
    fclose(file);
    node_state_destroy(out_state);
    return false;
  }
  fclose(file);
  return true;
}

static bool parse_hex_blob(const char *hex, uint8_t **out_bytes,
                           size_t *out_size) {
  EVM_Status status = evm_load_hex(hex, out_bytes, out_size);
  if (status != EVM_OK) {
    fprintf(stderr, "Hex parse failed: %s\n", evm_status_string(status));
    return false;
  }
  return true;
}

static bool parse_word(const char *text, uint256_t *out_word) {
  if (text == nullptr || out_word == nullptr) {
    return false;
  }

  if ((strncmp(text, "0x", 2) == 0) || (strncmp(text, "0X", 2) == 0)) {
    const char *hex_digits = text + 2;
    size_t digits_len = strlen(hex_digits);
    char *normalized = nullptr;
    const char *parse_text = text;
    if ((digits_len % 2U) != 0U) {
      size_t normalized_size = 0U;
      if (!checked_add_size(digits_len, 4U, &normalized_size)) {
        fprintf(stderr, "Hex word too large: %s\n", text);
        return false;
      }
      normalized = calloc(normalized_size, sizeof(char));
      if (normalized == nullptr) {
        fprintf(stderr, "Out of memory while normalizing hex word\n");
        return false;
      }
      normalized[0] = '0';
      normalized[1] = 'x';
      normalized[2] = '0';
      memcpy(normalized + 3U, hex_digits, digits_len);
      parse_text = normalized;
    }

    uint8_t *bytes = nullptr;
    size_t size = 0;
    if (!parse_hex_blob(parse_text, &bytes, &size)) {
      free(normalized);
      return false;
    }
    if (size > 32U) {
      fprintf(stderr, "Word too wide (>32 bytes): %s\n", text);
      free(bytes);
      free(normalized);
      return false;
    }

    uint8_t padded[32] = {0};
    memcpy(padded + (32U - size), bytes, size);
    uint256_from_be_bytes(out_word, padded);
    free(bytes);
    free(normalized);
    return true;
  }

  const char *cursor = text;
  if (*cursor == '+') {
    ++cursor;
  }
  if (*cursor == '\0' || *cursor == '-') {
    fprintf(stderr, "Invalid integer word: %s\n", text);
    return false;
  }

  uint256_t value = uint256_zero();
  for (; *cursor != '\0'; ++cursor) {
    if (*cursor < '0' || *cursor > '9') {
      fprintf(stderr, "Invalid integer word: %s\n", text);
      return false;
    }

    uint64_t carry = (uint64_t)(*cursor - '0');
    for (size_t limb = 0; limb < 4U; ++limb) {
      uint64_t current = value.limbs[limb];
      uint64_t mul8 = current << 3U;
      uint64_t mul2 = current << 1U;
      uint64_t product_lo = mul8 + mul2;
      uint64_t product_hi =
          (current >> 61U) + (current >> 63U) + ((product_lo < mul8) ? 1U : 0U);

      uint64_t next = product_lo + carry;
      if (next < product_lo) {
        ++product_hi;
      }

      value.limbs[limb] = next;
      carry = product_hi;
    }

    if (carry != 0U) {
      fprintf(stderr, "Word too large for uint256: %s\n", text);
      return false;
    }
  }

  *out_word = value;
  return true;
}

static bool parse_command_arg_index(const char *option, size_t *out_index) {
  if (option == nullptr || out_index == nullptr) {
    return false;
  }
  if (strncmp(option, "--arg", 5U) != 0) {
    return false;
  }

  const char *digits = option + 5U;
  if (*digits == '\0') {
    return false;
  }

  size_t index = 0;
  for (const char *cursor = digits; *cursor != '\0'; ++cursor) {
    if (*cursor < '0' || *cursor > '9') {
      return false;
    }

    size_t digit = (size_t)(*cursor - '0');
    if (index > ((SIZE_MAX - digit) / 10U)) {
      return false;
    }
    index = (index * 10U) + digit;
  }

  if (index == 0U) {
    return false;
  }
  *out_index = index;
  return true;
}

static bool command_words_ensure_size(uint256_t **words, size_t *word_count,
                                      size_t target_count) {
  if (words == nullptr || word_count == nullptr) {
    return false;
  }
  if (target_count <= *word_count) {
    return true;
  }
  size_t resized_bytes = 0U;
  if (!checked_mul_size(target_count, sizeof(**words), &resized_bytes)) {
    return false;
  }
  size_t added_words = target_count - *word_count;
  size_t added_bytes = 0U;
  if (!checked_mul_size(added_words, sizeof(**words), &added_bytes)) {
    return false;
  }

  uint256_t *resized = realloc(*words, resized_bytes);
  if (resized == nullptr) {
    return false;
  }

  memset(resized + *word_count, 0, added_bytes);
  *words = resized;
  *word_count = target_count;
  return true;
}

static bool compile_source(const char *path, uint8_t **out_code,
                           size_t *out_size) {
  char *source = nullptr;
  if (!nano_utils_read_file_text(path, &source)) {
    fprintf(stderr, "Failed to read source file: %s\n", path);
    return false;
  }

  char error[256] = {0};
  NanoSol_Status status =
      nanosol_compile(source, out_code, out_size, error, sizeof(error));
  free(source);
  if (status != NANOSOL_OK) {
    fprintf(stderr, "Compilation failed (%s): %s\n",
            nanosol_status_string(status), error);
    return false;
  }
  return true;
}

static bool vm_take_state_from_node(EVM_State *vm, NodeState *state) {
  if (vm == nullptr || state == nullptr) {
    return false;
  }
  if ((state->storage_count > 0U && state->storage == nullptr) ||
      (state->transient_storage_count > 0U &&
       state->transient_storage == nullptr) ||
      (state->runtime_accounts_count > 0U &&
       state->runtime_accounts == nullptr)) {
    return false;
  }

  normalize_storage_entries(state->storage, state->storage_count);
  for (size_t i = 0; i < state->runtime_accounts_count; ++i) {
    normalize_storage_entries(state->runtime_accounts[i].storage,
                              state->runtime_accounts[i].storage_count);
    state->runtime_accounts[i].created_in_transaction = false;
  }

  vm->storage = state->storage;
  vm->storage_count = state->storage_count;
  vm->storage_capacity = state->storage_count;
  state->storage = nullptr;
  state->storage_count = 0;

  vm->transient_storage = state->transient_storage;
  vm->transient_storage_count = state->transient_storage_count;
  vm->transient_storage_capacity = state->transient_storage_count;
  state->transient_storage = nullptr;
  state->transient_storage_count = 0;

  vm->runtime_accounts = state->runtime_accounts;
  vm->runtime_accounts_count = state->runtime_accounts_count;
  vm->runtime_accounts_capacity = state->runtime_accounts_count;
  state->runtime_accounts = nullptr;
  state->runtime_accounts_count = 0;

  vm->self_balance = state->self_balance;
  return true;
}

static bool node_state_take_storage_from_vm(NodeState *state, EVM_State *vm) {
  if (state == nullptr || vm == nullptr) {
    return false;
  }

  free(state->storage);
  free(state->transient_storage);
  runtime_accounts_reset(state->runtime_accounts,
                         state->runtime_accounts_count);
  state->storage = vm->storage;
  state->storage_count = vm->storage_count;
  state->transient_storage = vm->transient_storage;
  state->transient_storage_count = vm->transient_storage_count;
  state->runtime_accounts = vm->runtime_accounts;
  state->runtime_accounts_count = vm->runtime_accounts_count;
  state->self_balance = vm->self_balance;

  normalize_storage_entries(state->storage, state->storage_count);
  for (size_t i = 0; i < state->runtime_accounts_count; ++i) {
    normalize_storage_entries(state->runtime_accounts[i].storage,
                              state->runtime_accounts[i].storage_count);
    state->runtime_accounts[i].created_in_transaction = false;
  }

  vm->storage = nullptr;
  vm->storage_count = 0;
  vm->storage_capacity = 0;
  vm->transient_storage = nullptr;
  vm->transient_storage_count = 0;
  vm->transient_storage_capacity = 0;
  vm->runtime_accounts = nullptr;
  vm->runtime_accounts_count = 0;
  vm->runtime_accounts_capacity = 0;
  vm->self_balance = uint256_zero();
  return true;
}

static bool build_word_calldata(const uint256_t *words, size_t word_count,
                                uint8_t **out_bytes, size_t *out_size) {
  if (out_bytes == nullptr || out_size == nullptr) {
    return false;
  }
  if (word_count == 0U) {
    *out_bytes = nullptr;
    *out_size = 0U;
    return true;
  }
  if (words == nullptr || word_count > (SIZE_MAX / 32U)) {
    return false;
  }

  size_t calldata_size = word_count * 32U;
  uint8_t *buffer = calloc(calldata_size, sizeof(uint8_t));
  if (buffer == nullptr) {
    return false;
  }

  for (size_t i = 0; i < word_count; ++i) {
    uint256_to_be_bytes(&words[i], buffer + (i * 32U));
  }

  *out_bytes = buffer;
  *out_size = calldata_size;
  return true;
}

static int command_deploy(int argc, char **argv) {
  const char *state_path = nullptr;
  const char *source_path = nullptr;
  const char *bytecode_hex = nullptr;
  uint256_t contract_address = uint256_from_u64(DEFAULT_CONTRACT_ADDRESS);

  for (int i = 0; i < argc; ++i) {
    if (strcmp(argv[i], "--state") == 0) {
      if (i + 1 >= argc) {
        fprintf(stderr, "--state requires a value\n");
        return 1;
      }
      state_path = argv[++i];
      continue;
    }
    if (strcmp(argv[i], "--source") == 0) {
      if (i + 1 >= argc) {
        fprintf(stderr, "--source requires a value\n");
        return 1;
      }
      source_path = argv[++i];
      continue;
    }
    if (strcmp(argv[i], "--bytecode") == 0) {
      if (i + 1 >= argc) {
        fprintf(stderr, "--bytecode requires a value\n");
        return 1;
      }
      bytecode_hex = argv[++i];
      continue;
    }
    if (strcmp(argv[i], "--address") == 0) {
      if (i + 1 >= argc) {
        fprintf(stderr, "--address requires a value\n");
        return 1;
      }
      if (!parse_word(argv[++i], &contract_address)) {
        return 1;
      }
      continue;
    }

    fprintf(stderr, "Unknown deploy option: %s\n", argv[i]);
    return 1;
  }

  if (state_path == nullptr) {
    fprintf(stderr, "deploy requires --state <file>\n");
    return 1;
  }
  if ((source_path == nullptr) == (bytecode_hex == nullptr)) {
    fprintf(stderr, "deploy requires exactly one of --source or --bytecode\n");
    return 1;
  }

  uint8_t *code = nullptr;
  size_t code_size = 0;
  if (source_path != nullptr) {
    if (!compile_source(source_path, &code, &code_size)) {
      return 1;
    }
  } else {
    if (!parse_hex_blob(bytecode_hex, &code, &code_size)) {
      return 1;
    }
  }

  NodeState state;
  node_state_init(&state);
  state.code = code;
  state.code_size = code_size;
  state.contract_address = contract_address;

  bool saved = node_state_save(state_path, &state);
  if (!saved) {
    node_state_destroy(&state);
    return 1;
  }

  printf("deployed: yes\n");
  printf("state_file: %s\n", state_path);
  printf("code_size: %zu\n", state.code_size);
  fputs("contract_address: ", stdout);
  nano_utils_print_uint256_hex(&state.contract_address);
  fputc('\n', stdout);

  node_state_destroy(&state);
  return 0;
}

static int command_call(int argc, char **argv) {
  const char *state_path = nullptr;
  const char *calldata_hex = nullptr;
  uint64_t gas_limit = DEFAULT_GAS_LIMIT;
  uint256_t caller = uint256_from_u64(DEFAULT_CALLER);
  uint256_t call_value = uint256_zero();

  bool command_mode = false;
  uint256_t *command_words = nullptr;
  size_t command_word_count = 0;

  for (int i = 0; i < argc; ++i) {
    if (strcmp(argv[i], "--state") == 0) {
      if (i + 1 >= argc) {
        fprintf(stderr, "--state requires a value\n");
        free(command_words);
        return 1;
      }
      state_path = argv[++i];
      continue;
    }
    if (strcmp(argv[i], "--calldata") == 0) {
      if (i + 1 >= argc) {
        fprintf(stderr, "--calldata requires a value\n");
        free(command_words);
        return 1;
      }
      calldata_hex = argv[++i];
      continue;
    }
    if (strcmp(argv[i], "--cmd") == 0) {
      if (i + 1 >= argc) {
        fprintf(stderr, "--cmd requires a value\n");
        free(command_words);
        return 1;
      }
      if (!command_words_ensure_size(&command_words, &command_word_count, 1U)) {
        fprintf(stderr, "Out of memory while parsing command arguments\n");
        free(command_words);
        return 1;
      }
      if (!parse_word(argv[++i], &command_words[0])) {
        free(command_words);
        return 1;
      }
      command_mode = true;
      continue;
    }

    if (strncmp(argv[i], "--arg", 5U) == 0) {
      size_t arg_index = 0;
      if (!parse_command_arg_index(argv[i], &arg_index)) {
        fprintf(stderr, "Invalid command argument option: %s\n", argv[i]);
        free(command_words);
        return 1;
      }
      if (i + 1 >= argc) {
        fprintf(stderr, "%s requires a value\n", argv[i]);
        free(command_words);
        return 1;
      }
      if (arg_index == SIZE_MAX) {
        fprintf(stderr, "Command argument index too large: %s\n", argv[i]);
        free(command_words);
        return 1;
      }
      if (!command_words_ensure_size(&command_words, &command_word_count,
                                     arg_index + 1U)) {
        fprintf(stderr, "Out of memory while parsing command arguments\n");
        free(command_words);
        return 1;
      }
      if (!parse_word(argv[++i], &command_words[arg_index])) {
        free(command_words);
        return 1;
      }
      continue;
    }
    if (strcmp(argv[i], "--caller") == 0) {
      if (i + 1 >= argc) {
        fprintf(stderr, "--caller requires a value\n");
        free(command_words);
        return 1;
      }
      if (!parse_word(argv[++i], &caller)) {
        free(command_words);
        return 1;
      }
      continue;
    }
    if (strcmp(argv[i], "--value") == 0) {
      if (i + 1 >= argc) {
        fprintf(stderr, "--value requires a value\n");
        free(command_words);
        return 1;
      }
      if (!parse_word(argv[++i], &call_value)) {
        free(command_words);
        return 1;
      }
      continue;
    }
    if (strcmp(argv[i], "--gas") == 0) {
      if (i + 1 >= argc) {
        fprintf(stderr, "--gas requires a value\n");
        free(command_words);
        return 1;
      }
      if (!nano_utils_parse_u64(argv[++i], &gas_limit)) {
        fprintf(stderr, "Invalid integer: %s\n", argv[i]);
        free(command_words);
        return 1;
      }
      continue;
    }

    fprintf(stderr, "Unknown call option: %s\n", argv[i]);
    free(command_words);
    return 1;
  }

  if (state_path == nullptr) {
    fprintf(stderr, "call requires --state <file>\n");
    free(command_words);
    return 1;
  }
  if (calldata_hex != nullptr && command_mode) {
    fprintf(stderr, "Use either --calldata or --cmd/--argN, not both\n");
    free(command_words);
    return 1;
  }
  if (command_word_count > 0U && !command_mode) {
    fprintf(stderr, "Command arguments require --cmd <word>\n");
    free(command_words);
    return 1;
  }

  NodeState state;
  if (!node_state_load(state_path, &state)) {
    free(command_words);
    return 1;
  }

  uint8_t *calldata = nullptr;
  size_t calldata_size = 0;
  if (calldata_hex != nullptr) {
    if (!parse_hex_blob(calldata_hex, &calldata, &calldata_size)) {
      node_state_destroy(&state);
      return 1;
    }
  } else if (command_mode) {
    if (!build_word_calldata(command_words, command_word_count, &calldata,
                             &calldata_size)) {
      fprintf(stderr, "Failed to allocate command calldata\n");
      free(command_words);
      node_state_destroy(&state);
      return 1;
    }
  }
  free(command_words);

  EVM_State vm;
  EVM_Status status = evm_init(&vm, state.code, state.code_size, gas_limit);
  if (status != EVM_OK) {
    fprintf(stderr, "VM init failed: %s\n", evm_status_string(status));
    free(calldata);
    node_state_destroy(&state);
    return 1;
  }

  if (!vm_take_state_from_node(&vm, &state)) {
    fprintf(stderr, "Failed to seed VM state\n");
    free(calldata);
    evm_destroy(&vm);
    node_state_destroy(&state);
    return 1;
  }

  vm.address = state.contract_address;
  vm.caller = caller;
  vm.origin = caller;
  vm.call_value = call_value;
  vm.call_data = calldata;
  vm.call_data_size = calldata_size;

  status = evm_execute(&vm);

  printf("status: %s\n", evm_status_string(status));
  printf("pc: %zu\n", vm.pc);
  printf("gas_remaining: %" PRIu64 "\n", vm.gas_remaining);
  printf("storage_count: %zu\n", vm.storage_count);
  printf("logs_count: %zu\n", vm.logs_count);
  printf("stack_depth: %zu\n", stack_depth(&vm.stack));

  uint256_t stack_top = uint256_zero();
  if (stack_peek(&vm.stack, &stack_top) == STACK_OK) {
    fputs("stack_top: ", stdout);
    nano_utils_print_uint256_hex(&stack_top);
    fputc('\n', stdout);
  } else {
    puts("stack_top: <empty>");
  }

  if (vm.return_data_size > 0U) {
    fputs("return_data: ", stdout);
    nano_utils_print_bytes_hex(vm.return_data, vm.return_data_size);
    fputc('\n', stdout);
  } else {
    puts("return_data: <empty>");
  }

  int result = (status == EVM_OK) ? 0 : 2;
  if (status == EVM_OK) {
    bool update_ok = node_state_take_storage_from_vm(&state, &vm);
    if (!update_ok || !node_state_save(state_path, &state)) {
      fprintf(stderr, "Failed to persist updated state\n");
      result = 1;
    } else {
      puts("state_persisted: yes");
    }
  } else {
    puts("state_persisted: no");
  }

  free(calldata);
  evm_destroy(&vm);
  node_state_destroy(&state);
  return result;
}

static int command_inspect(int argc, char **argv) {
  const char *state_path = nullptr;
  for (int i = 0; i < argc; ++i) {
    if (strcmp(argv[i], "--state") == 0) {
      if (i + 1 >= argc) {
        fprintf(stderr, "--state requires a value\n");
        return 1;
      }
      state_path = argv[++i];
      continue;
    }

    fprintf(stderr, "Unknown inspect option: %s\n", argv[i]);
    return 1;
  }

  if (state_path == nullptr) {
    fprintf(stderr, "inspect requires --state <file>\n");
    return 1;
  }

  NodeState state;
  if (!node_state_load(state_path, &state)) {
    return 1;
  }

  printf("state_file: %s\n", state_path);
  fputs("contract_address: ", stdout);
  nano_utils_print_uint256_hex(&state.contract_address);
  fputc('\n', stdout);
  printf("code_size: %zu\n", state.code_size);
  printf("storage_count: %zu\n", state.storage_count);

  fputs("code_hex: ", stdout);
  nano_utils_print_bytes_hex(state.code, state.code_size);
  fputc('\n', stdout);

  for (size_t i = 0; i < state.storage_count; ++i) {
    printf("storage[%zu].key=", i);
    nano_utils_print_uint256_hex(&state.storage[i].key);
    fputs(" value=", stdout);
    nano_utils_print_uint256_hex(&state.storage[i].value);
    fputc('\n', stdout);
  }

  node_state_destroy(&state);
  return 0;
}

static int command_reset(int argc, char **argv) {
  const char *state_path = nullptr;
  for (int i = 0; i < argc; ++i) {
    if (strcmp(argv[i], "--state") == 0) {
      if (i + 1 >= argc) {
        fprintf(stderr, "--state requires a value\n");
        return 1;
      }
      state_path = argv[++i];
      continue;
    }

    fprintf(stderr, "Unknown reset option: %s\n", argv[i]);
    return 1;
  }

  if (state_path == nullptr) {
    fprintf(stderr, "reset requires --state <file>\n");
    return 1;
  }

  if (remove(state_path) != 0) {
    if (errno == ENOENT) {
      printf("state already absent: %s\n", state_path);
      return 0;
    }
    fprintf(stderr, "Failed to remove state file: %s\n", state_path);
    return 1;
  }

  printf("state removed: %s\n", state_path);
  return 0;
}

int main(int argc, char **argv) {
  if (argc < 2) {
    print_usage(argv[0]);
    return 1;
  }

  const char *command = argv[1];
  if (strcmp(command, "deploy") == 0) {
    return command_deploy(argc - 2, argv + 2);
  }
  if (strcmp(command, "call") == 0) {
    return command_call(argc - 2, argv + 2);
  }
  if (strcmp(command, "inspect") == 0) {
    return command_inspect(argc - 2, argv + 2);
  }
  if (strcmp(command, "reset") == 0) {
    return command_reset(argc - 2, argv + 2);
  }

  fprintf(stderr, "Unknown command: %s\n", command);
  print_usage(argv[0]);
  return 1;
}
