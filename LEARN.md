# Nano EVM Learning Path

This document is a guided tour for students. Follow it in order: **Easy -> Medium -> Harder**.

## 0) Quick Start (10-15 min)

Build and run everything once:

```bash
zig build
zig build test
zig build solc
zig build examples
```

Run a tiny bytecode program (`2 + 3`):

```bash
zig-out/bin/nano-evm 6002600301
```

Compile a toy contract and run it:

```bash
zig-out/bin/nano-solc examples/simple.nsol --run 100000
```

Start from these entry points:

- VM CLI: [`src/main.c`](src/main.c)
- Compiler CLI: [`src/nanosol_main.c`](src/nanosol_main.c)
- Public VM API/types: [`include/evm.h`](include/evm.h)
- Public compiler API: [`include/nanosol.h`](include/nanosol.h)

---

## 0.5) How EVM Works (Mental Model)

The EVM is a **256-bit stack machine**. It executes bytecode from program counter `pc = 0` until it hits `STOP`, `RETURN`, `REVERT`, or an error.

### Execution cycle in this codebase

For each instruction, the VM does this:

1. Fetch opcode from code and advance `pc`:
- [`src/evm/execution.c`](src/evm/execution.c)

2. Charge base gas from the opcode table:
- [`src/evm/common.c`](src/evm/common.c)

3. Execute opcode logic (stack pops/pushes, memory/storage/account effects), sometimes charging additional dynamic gas:
- [`src/evm/execution.c`](src/evm/execution.c)
- [`src/evm/gas_and_storage.c`](src/evm/gas_and_storage.c)

4. Continue until a terminal state (`STOP`/`RETURN`/`REVERT`) or error status:
- [`include/evm.h`](include/evm.h)
- [`src/evm/api.c`](src/evm/api.c)

### Core EVM data areas

- **Stack**: fixed max depth 1024 words (32 bytes each), LIFO push/pop/peek.
- [`include/stack.h`](include/stack.h)
- [`src/stack.c`](src/stack.c)

- **Memory**: linear byte array, expands in 32-byte words, paid by expansion gas.
- [`src/evm/execution.c`](src/evm/execution.c)
- [`src/evm/common.c`](src/evm/common.c)

- **Storage**: persistent key-value mapping (`uint256 -> uint256`) with warm/cold and refund-aware semantics.
- [`src/evm/state.c`](src/evm/state.c)
- [`src/evm/gas_and_storage.c`](src/evm/gas_and_storage.c)

- **Transient storage**: internal temporary per-transaction storage reset at top-level execution. (`TLOAD`/`TSTORE` currently decode to `INVALID_OPCODE` in this VM.)
- [`src/evm/execution.c`](src/evm/execution.c)
- [`src/evm/state.c`](src/evm/state.c)

- **Return data**: buffer produced by `RETURN`, `REVERT`, and external calls.
- [`src/evm/return_data_and_hash.c`](src/evm/return_data_and_hash.c)

### Control flow and jump safety

`JUMP`/`JUMPI` are only valid to `JUMPDEST` locations. This implementation precomputes a jumpdest bitmap to validate destinations efficiently.

- [`src/evm/execution.c`](src/evm/execution.c)
- [`tests/test_invalid_opcode_and_bytecode.c`](tests/test_invalid_opcode_and_bytecode.c)

### Gas and refunds (why some runs fail with OUT_OF_GAS)

- Base gas: opcode-specific table.
- Dynamic gas: memory expansion, copy cost, `SHA3`, `SSTORE`, call forwarding, etc.
- Refunds: tracked and applied at top-level completion (capped).

Main files:

- [`src/evm/common.c`](src/evm/common.c)
- [`src/evm/gas_and_storage.c`](src/evm/gas_and_storage.c)
- [`tests/test_out_of_gas.c`](tests/test_out_of_gas.c)
- [`tests/test_per_opcode_gas.c`](tests/test_per_opcode_gas.c)

### Calls, creates, and precompiles

`CALL`/`DELEGATECALL`/`STATICCALL` and `CREATE`/`CREATE2` run through child execution contexts. Child state is merged on success and rolled back on recoverable failure. Precompiles are handled via dedicated routines.

- [`src/evm/call_and_create.c`](src/evm/call_and_create.c)
- [`src/evm/state.c`](src/evm/state.c)
- [`tests/test_new_call_create_and_selfdestruct_opcodes.c`](tests/test_new_call_create_and_selfdestruct_opcodes.c)
- [`tests/test_precompile_dispatch.c`](tests/test_precompile_dispatch.c)

### `RETURN` vs `REVERT`

- `RETURN`: sets return bytes and completes normally.
- `REVERT`: sets return bytes and rolls back storage/log changes for the current frame.
- Direct frame execution returns `EVM_ERR_REVERT`; inside `CALL`/`CREATE`, it is treated as a recoverable child failure (call success flag `0`) unless an internal error occurs.

- [`src/evm/execution.c`](src/evm/execution.c)
- [`src/evm/state.c`](src/evm/state.c)
- [`tests/test_return_and_revert.c`](tests/test_return_and_revert.c)

### Fast trace exercise

Trace this bytecode: `602a60005260005100`

1. `PUSH1 0x2a`
2. `PUSH1 0x00`
3. `MSTORE`
4. `PUSH1 0x00`
5. `MLOAD`
6. `STOP`

Use:

- [`src/main.c`](src/main.c)
- [`src/evm/execution.c`](src/evm/execution.c)
- [`tests/test_memory_ops.c`](tests/test_memory_ops.c)

---

## 1) Easy: Core VM Foundations

Goal: understand how values, stack, and basic execution plumbing work.

### Read in this order

1. 256-bit value type and math:
- [`include/uint256.h`](include/uint256.h)
- [`src/uint256.c`](src/uint256.c)

2. Stack implementation:
- [`include/stack.h`](include/stack.h)
- [`src/stack.c`](src/stack.c)

3. Hex input + status surface:
- [`src/evm/api.c`](src/evm/api.c)
- [`src/evm/common.c`](src/evm/common.c)

4. How CLI wires it together:
- [`src/main.c`](src/main.c)

### Checkpoint tests

- Arithmetic and stack behavior: [`tests/test_arithmetic_and_stack.c`](tests/test_arithmetic_and_stack.c)
- uint256 + stack helper coverage: [`tests/test_uint256_and_stack_helpers.c`](tests/test_uint256_and_stack_helpers.c)
- Hex parsing behavior: [`tests/test_hex_parser.c`](tests/test_hex_parser.c)

### Easy exercises

- Trace one full run of `6002600301` from `main()` into `evm_load_hex()`, `evm_init()`, and `evm_execute()`.
- In [`src/uint256.c`](src/uint256.c), explain why arithmetic naturally wraps at 256 bits.
- Add your own tiny test next to [`tests/test_arithmetic_and_stack.c`](tests/test_arithmetic_and_stack.c) for an edge case (for example, divide by zero).

---

## 2) Medium: Opcode Engine, Memory/Gas, and NanoSol Compiler Basics

Goal: understand interpreter control flow and how NanoSol compiles to bytecode.

### Read in this order

1. Dispatcher and opcode loop:
- [`src/evm/execution.c`](src/evm/execution.c)

2. Gas charging and memory/storage helpers:
- [`src/evm/gas_and_storage.c`](src/evm/gas_and_storage.c)
- [`src/evm/state.c`](src/evm/state.c)
- [`src/evm/return_data_and_hash.c`](src/evm/return_data_and_hash.c)

3. How modules are composed:
- [`src/evm.c`](src/evm.c)

4. NanoSol compiler surface and parser/emitter pieces:
- [`src/nanosol_main.c`](src/nanosol_main.c)
- [`src/nanosol/api.c`](src/nanosol/api.c)
- [`src/nanosol/expression.c`](src/nanosol/expression.c)
- [`src/nanosol/statement.c`](src/nanosol/statement.c)
- [`src/nanosol/program.c`](src/nanosol/program.c)
- [`src/nanosol.c`](src/nanosol.c)

### Checkpoint tests

- Memory behavior: [`tests/test_memory_ops.c`](tests/test_memory_ops.c)
- Storage behavior: [`tests/test_storage_ops.c`](tests/test_storage_ops.c)
- Return/revert behavior: [`tests/test_return_and_revert.c`](tests/test_return_and_revert.c)
- Out-of-gas behavior: [`tests/test_out_of_gas.c`](tests/test_out_of_gas.c)
- NanoSol control flow + storage: [`tests/test_nanosol_compiler_control_flow_and_storage.c`](tests/test_nanosol_compiler_control_flow_and_storage.c)

### Medium exercises

- Pick one opcode (for example `SSTORE` or `CALLDATACOPY`) and trace it from the switch in [`src/evm/execution.c`](src/evm/execution.c) into helper logic.
- Compare a small `.nsol` program with its emitted opcodes via [`src/nanosol_main.c`](src/nanosol_main.c).
- Add one NanoSol compiler semantic-error test similar to [`tests/test_nanosol_compiler_semantic_error.c`](tests/test_nanosol_compiler_semantic_error.c).

Use these example contracts while tracing:

- [`examples/simple.nsol`](examples/simple.nsol)
- [`examples/loop_sum.nsol`](examples/loop_sum.nsol)
- [`examples/storage_counter.nsol`](examples/storage_counter.nsol)
- [`examples/calldata_gate.nsol`](examples/calldata_gate.nsol)

---

## 3) Harder: Calls/Creates, Precompiles, Persistent State Node

Goal: understand cross-account execution, precompile internals, and state persistence.

### Read in this order

1. Call/create execution and precompiles:
- [`src/evm/call_and_create.c`](src/evm/call_and_create.c)
- [`src/evm/bn254_pairing.c`](src/evm/bn254_pairing.c)

2. Runtime account/state lifecycle:
- [`src/evm/state.c`](src/evm/state.c)

3. Persistent node-style runner and on-disk state format:
- [`src/nano_node.c`](src/nano_node.c)

4. Contract registry and runnable demos:
- [`include/contracts.h`](include/contracts.h)
- [`src/contracts.c`](src/contracts.c)
- [`src/contracts_examples.c`](src/contracts_examples.c)

### Checkpoint tests

- Call/create/selfdestruct flow: [`tests/test_new_call_create_and_selfdestruct_opcodes.c`](tests/test_new_call_create_and_selfdestruct_opcodes.c)
- Precompile routing: [`tests/test_precompile_dispatch.c`](tests/test_precompile_dispatch.c)
- Call frame persistence: [`tests/test_call_frame_state_persistence.c`](tests/test_call_frame_state_persistence.c)
- CREATE2 details: [`tests/test_create2_increments_sender_nonce_for_create_addressing.c`](tests/test_create2_increments_sender_nonce_for_create_addressing.c)
- BN254 pairing input validation: [`tests/test_bn254_pairing_api_input_validation.c`](tests/test_bn254_pairing_api_input_validation.c)

### Harder projects

- Add a new built-in contract entry in [`src/contracts.c`](src/contracts.c), then validate it in [`tests/test_contracts_module.c`](tests/test_contracts_module.c).
- Extend `nano-node` command behavior in [`src/nano_node.c`](src/nano_node.c) and add end-to-end tests.
- Add one new NanoSol builtin and wire parsing + emission through [`src/nanosol/expression.c`](src/nanosol/expression.c), [`src/nanosol/statement.c`](src/nanosol/statement.c), [`tests/test_nanosol_compiler_arithmetic_return.c`](tests/test_nanosol_compiler_arithmetic_return.c), [`tests/test_nanosol_compiler_control_flow_and_storage.c`](tests/test_nanosol_compiler_control_flow_and_storage.c), [`tests/test_nanosol_compiler_semantic_error.c`](tests/test_nanosol_compiler_semantic_error.c), and [`tests/test_nanosol_compiler_unterminated_block_comment.c`](tests/test_nanosol_compiler_unterminated_block_comment.c).

---

## Useful Reference Map

- Build/test wiring: [`build.zig`](build.zig)
- One-command shortcuts: [`justfile`](justfile)
- Full test runner entry: [`tests/test_suite.c`](tests/test_suite.c)
- Opcode constants: [`include/opcodes.h`](include/opcodes.h)
- Utilities used by CLIs/compiler: [`include/nano_utils.h`](include/nano_utils.h)

## Glossary

- **Account**: EVM address-scoped state (balance, nonce, code, storage); modeled here with external and runtime account structures in [`include/evm.h`](include/evm.h) and managed in [`src/evm/state.c`](src/evm/state.c).
- **ABI (Application Binary Interface)**: Convention for encoding/decoding function inputs and outputs in calldata/return data; see command-style examples in [`README.md`](README.md) and [`src/nano_node.c`](src/nano_node.c).
- **Bytecode**: Raw bytes executed by the VM opcode loop; loaded/parsing in [`src/evm/api.c`](src/evm/api.c), executed in [`src/evm/execution.c`](src/evm/execution.c).
- **Calldata**: Read-only input bytes supplied to a call frame; consumed by opcodes like `CALLDATALOAD`/`CALLDATACOPY` in [`src/evm/execution.c`](src/evm/execution.c).
- **Call frame**: One execution context in a call/create tree (its own `pc`, stack, memory, gas slice, returndata); created/merged in [`src/evm/call_and_create.c`](src/evm/call_and_create.c).
- **Call depth**: Nesting level of frames; bounded to prevent unbounded recursion, checked during call/create handling in [`src/evm/call_and_create.c`](src/evm/call_and_create.c).
- **EVM status**: Execution result code (`OK`, `OUT_OF_GAS`, `REVERT`, etc.) defined in [`include/evm.h`](include/evm.h), stringified in [`src/evm/api.c`](src/evm/api.c).
- **Gas**: Computational budget consumed per opcode and dynamic behavior (memory expansion, storage writes, calls); core logic in [`src/evm/common.c`](src/evm/common.c) and [`src/evm/gas_and_storage.c`](src/evm/gas_and_storage.c).
- **Gas refund**: Gas credited back under specific rules (for example certain storage transitions), tracked via `refund_counter` and applied in [`src/evm/gas_and_storage.c`](src/evm/gas_and_storage.c).
- **Jumpdest bitmap**: Precomputed map of legal `JUMPDEST` offsets used to validate `JUMP`/`JUMPI` targets; built in [`src/evm/execution.c`](src/evm/execution.c).
- **Memory**: Expandable, zero-initialized byte array local to one frame; expansion and charging handled by `evm_memory_ensure` in [`src/evm/execution.c`](src/evm/execution.c).
- **Opcode**: One-byte instruction (`ADD`, `SLOAD`, `CALL`, etc.); constants in [`include/opcodes.h`](include/opcodes.h), dispatch logic in [`src/evm/execution.c`](src/evm/execution.c).
- **Program counter (PC)**: Current code offset being executed; stored as `vm.pc` in [`include/evm.h`](include/evm.h) and advanced in [`src/evm/execution.c`](src/evm/execution.c).
- **Precompile**: Built-in native routine at reserved addresses (1..9 in this project) executed via special handling in [`src/evm/call_and_create.c`](src/evm/call_and_create.c).
- **Revert**: Exceptional completion that returns data but rolls back frame changes (storage/log side effects for that frame); top-level returns `EVM_ERR_REVERT`, while nested call/create treats it as recoverable failure. See [`src/evm/execution.c`](src/evm/execution.c) and [`src/evm/call_and_create.c`](src/evm/call_and_create.c).
- **Return data**: Byte buffer produced by `RETURN`/`REVERT` or child calls and readable with `RETURNDATA*`; helper functions in [`src/evm/return_data_and_hash.c`](src/evm/return_data_and_hash.c).
- **Runtime account**: Mutable in-transaction account snapshot used during execution/merging; lifecycle functions in [`src/evm/state.c`](src/evm/state.c).
- **Stack**: LIFO structure of 256-bit words with max depth 1024; API in [`include/stack.h`](include/stack.h), implementation in [`src/stack.c`](src/stack.c).
- **Storage**: Persistent key-value state (`SLOAD`/`SSTORE`) associated with an account across runs; modeled and indexed in [`src/evm/state.c`](src/evm/state.c).
- **Transient storage**: Per-transaction key-value state tracked in VM/runtime account structures and cleared at transaction boundaries; managed in [`src/evm/state.c`](src/evm/state.c) and reset in [`src/evm/execution.c`](src/evm/execution.c). (`TLOAD`/`TSTORE` opcodes currently return `INVALID_OPCODE`.)
- **Warm vs cold access**: Access-list state tracking for account/slot lookups that changes gas cost on first vs repeated access; implemented in [`src/evm/state.c`](src/evm/state.c) and charged in [`src/evm/gas_and_storage.c`](src/evm/gas_and_storage.c).
- **Word (EVM word)**: 32-byte (256-bit) value unit used by stack/storage and many opcode semantics; represented here by [`include/uint256.h`](include/uint256.h).
- **NanoSol**: Toy Solidity-like language in this repo that compiles to EVM bytecode; public API in [`include/nanosol.h`](include/nanosol.h) and implementation in [`src/nanosol.c`](src/nanosol.c).

## Suggested Study Rhythm

1. Read the files for one level.
2. Run tests related to that level.
3. Make one small change.
4. Re-run `zig build test` and write down what changed.

If you keep this loop, the codebase becomes manageable quickly.
