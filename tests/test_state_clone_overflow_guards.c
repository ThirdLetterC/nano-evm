#include "test_helpers.h"

#include "evm/state_internal.h"

void test_state_clone_overflow_guards() {
  EVM_State src = {0};
  EVM_State dst = {0};
  EVM_Status status = EVM_OK;

  src.warm_slots = (EVM_AccessEntry *)(uintptr_t)1U;
  src.warm_slots_count = SIZE_MAX;
  status = warm_slots_clone(&dst, &src);
  assert(status == EVM_ERR_RUNTIME);
  assert(dst.warm_slots == nullptr);
  assert(dst.warm_slots_count == 0U);
  assert(dst.warm_slots_capacity == 0U);

  src = (EVM_State){0};
  src.warm_accounts = (uint256_t *)(uintptr_t)1U;
  src.warm_accounts_count = SIZE_MAX;
  status = warm_accounts_clone(&dst, &src);
  assert(status == EVM_ERR_RUNTIME);
  assert(dst.warm_accounts == nullptr);
  assert(dst.warm_accounts_count == 0U);
  assert(dst.warm_accounts_capacity == 0U);

  src = (EVM_State){0};
  src.runtime_accounts = (EVM_RuntimeAccount *)(uintptr_t)1U;
  src.runtime_accounts_count = SIZE_MAX;
  status = runtime_accounts_clone(&dst, &src);
  assert(status == EVM_ERR_RUNTIME);
  assert(dst.runtime_accounts == nullptr);
  assert(dst.runtime_accounts_count == 0U);
  assert(dst.runtime_accounts_capacity == 0U);

  src = (EVM_State){0};
  src.runtime_accounts = nullptr;
  src.runtime_accounts_count = 1U;
  status = runtime_accounts_clone(&dst, &src);
  assert(status == EVM_ERR_INTERNAL);

  EVM_State vm = {0};
  EVM_State child = {0};
  child.logs = nullptr;
  child.logs_count = 1U;
  status = merge_child_logs(&vm, &child);
  assert(status == EVM_ERR_INTERNAL);
}
