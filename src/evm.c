// Core constants, gas tables, overflow helpers, and shared primitives.
#include "evm/common.c"

// Storage, warm access tracking, runtime account snapshots, and log merging.
#include "evm/state.c"

// Return-data/memory copy helpers and hash utility primitives.
#include "evm/return_data_and_hash.c"

// Dynamic gas charging, refunds, SSTORE semantics, and log appends.
#include "evm/gas_and_storage.c"

// Precompile execution and CREATE/CALL frame orchestration.
#include "evm/call_and_create.c"

// VM lifecycle and opcode interpreter loop.
#include "evm/execution.c"

// Hex loader and public status-to-string mapping.
#include "evm/api.c"
