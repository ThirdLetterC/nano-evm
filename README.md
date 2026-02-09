# Nano EVM

A compact Ethereum Virtual Machine runtime written in strict C23.

This repository ships three focused tools:

- `nano-evm`: execute raw hex bytecode in a single run
- `nano-node`: run one deployed contract against persistent local state
- `nano-solc`: compile a small Solidity-like language to EVM bytecode

The goal is predictable, inspectable execution for learning, testing, and
opcode-level experimentation.

## What It Does

`nano-evm` executes hex-encoded EVM bytecode with deterministic gas accounting,
explicit status reporting, and:

- 256-bit stack arithmetic/logic:
  `ADD`, `SUB`, `MUL`, `DIV`, `SDIV`, `MOD`, `SMOD`, `ADDMOD`, `MULMOD`, `EXP`,
  `SIGNEXTEND`,
  `LT`, `GT`, `SLT`, `SGT`, `EQ`, `ISZERO`, `AND`, `OR`, `XOR`, `NOT`, `BYTE`,
  `SHL`, `SHR`, `SAR`
- execution-context and chain opcodes:
  `ADDRESS`, `BALANCE`, `ORIGIN`, `CALLER`, `CALLVALUE`, `GASPRICE`,
  `BLOCKHASH`, `COINBASE`, `TIMESTAMP`, `NUMBER`, `PREVRANDAO`, `GASLIMIT`,
  `CHAINID`, `SELFBALANCE`, `BASEFEE`
- hashing via `SHA3` (Keccak-256)
- contract I/O introspection and copying:
  `CALLDATALOAD`, `CALLDATASIZE`, `CALLDATACOPY`,
  `CODESIZE`, `CODECOPY`, `EXTCODESIZE`, `EXTCODECOPY`, `EXTCODEHASH`,
  `RETURNDATASIZE`, `RETURNDATACOPY`
- stack machine with max depth `1024`
- linear memory with expansion gas charging
- key/value storage (`SLOAD`, `SSTORE`)
- `RETURN` and `REVERT` return-data handling
- call/create/system opcodes:
  `CREATE`, `CALL`, `CALLCODE`, `DELEGATECALL`, `CREATE2`, `STATICCALL`,
  `SELFDESTRUCT`
- log collection (`LOG0` to `LOG4`)
- gas accounting with Berlin-style warm/cold access and refunds
- currently treated as `INVALID_OPCODE` at runtime:
  `TLOAD`, `TSTORE`, `MCOPY`, `BLOBHASH`, `BLOBBASEFEE`
- explicit execution status codes

## Prerequisites

Install required build tools and system libraries (Debian/Ubuntu):

```bash
sudo apt update
sudo apt install -y build-essential zig libssl-dev libsecp256k1-dev libgmp-dev libb2-dev
```

## Build

```bash
zig build
```

Build the toy Solidity-like compiler:

```bash
zig build solc
```

Build the local stateful node-style runner:

```bash
zig build node
```

Build outputs are placed in `zig-out/bin`.

Default flags come from `build.zig`:

- `-std=c23`
- `-Wall -Wextra -Wpedantic -Werror`

## Test

```bash
zig build test
```

Run selected built-in smart-contract examples that currently execute successfully:

```bash
zig build examples -- adder storage_roundtrip
```

Note: `zig build examples` runs the full registry, including opcode-exerciser
contracts that intentionally hit currently invalid opcodes.

Debug sanitizer binaries are also available:

```bash
zig build debug
zig build test-debug
```

Note: LeakSanitizer can fail to run in ptrace-restricted environments.

## CLI Usage

```bash
zig-out/bin/nano-evm <hex-bytecode> [gas-limit]
```

- `hex-bytecode` accepts optional `0x` prefix.
- `gas-limit` defaults to `100000` when omitted.

Exit codes:

- `0`: execution finished with `OK`
- `1`: usage, parse, or VM initialization error
- `2`: execution failed with a non-`OK` EVM status

## Example

Run `PUSH1 0x02`, `PUSH1 0x03`, `ADD`:

```bash
zig-out/bin/nano-evm 6002600301
```

Sample output:

```text
status: OK
pc: 5
gas_remaining: 99991
stack_depth: 1
stack_top: 0x0000000000000000000000000000000000000000000000000000000000000005
```

## Local Node CLI

`nano-node` is a separate program for persistent single-contract state. It supports
deploying bytecode/source into a state file and then calling it repeatedly with calldata.

Deploy from NanoSol source:

```bash
zig-out/bin/nano-node deploy --state /tmp/erc20.state --source examples/erc20_token.nsol
```

Call using 4-word command ABI (`word0=cmd`, `word1..3=args`):

```bash
zig-out/bin/nano-node call --state /tmp/erc20.state --cmd 1 --caller 0xabc
zig-out/bin/nano-node call --state /tmp/erc20.state --cmd 2 --arg1 0xabc
zig-out/bin/nano-node call --state /tmp/erc20.state --cmd 3 --caller 0xabc --arg1 0xdef --arg2 100
```

Inspect/reset state:

```bash
zig-out/bin/nano-node inspect --state /tmp/erc20.state
zig-out/bin/nano-node reset --state /tmp/erc20.state
```

## NanoSol Toy Language

`nano-solc` compiles a deliberately small Solidity-like language into bytecode
targeting this VM. It is intended for quick experiments where you can
easily map source constructs to emitted opcodes.

Compile a source file and print bytecode + opcode disassembly:

```bash
zig-out/bin/nano-solc examples/simple.nsol
```

Compile and execute immediately:

```bash
zig-out/bin/nano-solc examples/simple.nsol --run 100000
```

Supported language subset:

- contract mode: `contract Name { function main() { ... } }`
- script mode: top-level statements (no contract/function wrapper)
- function declarations/calls with optional parameter annotations (`uint`/`let`)
- local declarations: `uint x = 42;` and `let x = 42;`
- assignment: `x = x + 1;`
- control flow: `if/else`, `while`, block scopes
- return: `return expression;` (returns 32-byte word)
- literals: decimal/hex (supports `_` separators), `true`, `false`
- expressions: variables, unary `!`/`-`, `+ - * / %`, `== != < > <= >=`,
  `&& ||` (short-circuit), `& | ^`, `<< >>`
- statement builtins: `sstore`, `tstore`, `mstore`, `mstore8`, `calldatacopy`,
  `codecopy`, `returndatacopy`, `mcopy`, `return_mem`, `revert_mem`,
  `selfdestruct`, `pop`
- expression builtins include: `sload`, `tload`, `mload`, `calldataload`,
  `balance`, `extcodesize`, `extcodehash`, `blockhash`, `keccak256`,
  `addmod`, `mulmod`, and context helpers such as `address()`, `caller()`,
  `timestamp()`, `number()`, `chainid()`, `gas()`, `msize()`,
  `returndatasize()`

Note: the compiler can emit `TLOAD`/`TSTORE`/`MCOPY`, but the VM currently
returns `INVALID_OPCODE` when executing them.

Example:

```solidity
contract Adder {
    function main() {
        uint a = 2;
        uint b = 3;
        return a + b;
    }
}
```

Example programs in `examples/`:

- `simple.nsol`: basic local vars and return expression
- `arithmetic_showcase.nsol`: arithmetic precedence and modulo
- `loop_sum.nsol`: `while` loop accumulation
- `storage_counter.nsol`: persistent storage `sload/sstore`
- `transient_cache.nsol`: transient storage `tload/tstore`
- `context_mix.nsol`: environment/context builtins + bitwise masking
- `calldata_gate.nsol`: branch on calldata size and `calldataload`
- `memory_return.nsol`: `mstore` + `return_mem`
- `revert_on_zero.nsol`: conditional `revert_mem`
- `operators_boolean.nsol`: boolean/logical operators and branching
- `bitshift_mask.nsol`: shift and mask operations
- `access_controlled_treasury.nsol`: admin-only pause/deposit/withdraw flow
- `timelock_vault.nsol`: beneficiary timelock with configurable unlock
- `rate_limiter.nsol`: per-block request throttling
- `oracle_sanity_guard.nsol`: reject outlier price updates
- `amm_quote.nsol`: constant-product swap quote with fee
- `linear_vesting.nsol`: linear vesting claimable amount/claim flow
- `replay_guard_transient.nsol`: transient nonce replay protection
- `erc20_token.nsol`: ERC-20-style token core with command ABI (`1` supply, `2` balance, `3` transfer, `4` approve, `5` allowance, `6` transferFrom)

## Smart Contract Module

The repository now includes a contract registry module:

- `include/contracts.h`
- `src/contracts.c`

Each built-in contract provides:

- `name`
- `description`
- `hex bytecode`
- `suggested_gas_limit`

Current built-ins:

Some built-ins are opcode exercisers for features not yet enabled in the runtime
and therefore currently return `INVALID_OPCODE`.

- `adder`: pushes `2` and `3`, then adds them
- `storage_roundtrip`: writes `slot[0] = 1`, then reads it back
- `return_one_byte`: returns `0xaa` as return-data
- `emit_log1`: emits one log with one topic and 1-byte payload
- `push0_increment`: uses `PUSH0` then adds `1`
- `dup_swap_add`: uses `DUP2`, `SWAP1`, and `POP` before `ADD`
- `jump_to_answer`: uses `JUMP`/`JUMPDEST` control flow
- `conditional_jump_true`: uses taken `JUMPI` branch
- `pc_then_gas_pop`: uses `PC`, `GAS`, and `POP`
- `lt_true`: compares `2 < 3` via `LT`
- `gt_true`: compares `3 > 2` via `GT`
- `signed_compare`: runs signed `SLT` and `SGT`
- `eq_iszero_false`: computes `ISZERO(EQ(0x2a, 0x2a))`
- `bitwise_chain`: chains `AND`, `OR`, `XOR`, `NOT`
- `byte_extract`: extracts one byte via `BYTE`
- `shift_roundtrip`: `SHL` then `SHR` round-trip with `SWAP1`
- `sar_negative_one`: arithmetic shift right (`SAR`) on `-1`
- `addmul_mod_mix`: combines `ADDMOD` and `MULMOD`
- `exp_signextend`: runs `EXP` then `SIGNEXTEND`
- `calldata_load_head`: reads the first calldata word via `CALLDATALOAD`
- `calldata_size_only`: pushes calldata length via `CALLDATASIZE`
- `calldata_copy_return4`: copies 4 calldata bytes via `CALLDATACOPY`, then returns them
- `codecopy_return2`: copies 2 bytes of runtime code via `CODECOPY`, then returns them
- `codesize_returndata_probe`: uses `CODESIZE`, `RETURNDATASIZE`, `RETURNDATACOPY`
- `sdiv_negative_two`: builds `-4` and uses `SDIV` by `2`
- `smod_negative_two`: builds `-5` and uses `SMOD` with modulus `3`
- `context_quad_add`: sums `ADDRESS`, `ORIGIN`, `CALLER`, and `CALLVALUE`
- `balance_plus_gasprice`: combines `BALANCE` and `GASPRICE`
- `extcodecopy_return2_zero`: runs `EXTCODECOPY` on unknown account, returns two bytes
- `blockhash_zero`: probes `BLOCKHASH` in default context
- `block_meta_sum`: combines `COINBASE`, `TIMESTAMP`, `NUMBER`, and `CHAINID`
- `transient_roundtrip`: writes via `TSTORE`, reads via `TLOAD`
- `mcopy_return4`: uses `MCOPY` and returns copied memory
- `create2_staticcall_selfdestruct`: exercises `CREATE2`, `STATICCALL`, `SELFDESTRUCT`
- `keccak_storage_commit`: hashes memory, stores hash in storage, returns hash
- `jump_table_arithmetic`: demonstrates branch/jump-table style arithmetic flow
- `calldata_dispatch_default`: dispatches on calldata size and returns fallback selector
- `log_topic_hash_return`: logs with a hash topic and returns that hash
- `transient_persistent_sum`: combines transient and persistent storage reads
- `mcopy_overlap_return4`: demonstrates overlapping memory copy via `MCOPY`
- `codecopy_sha3_return`: copies own code bytes and returns their `SHA3` hash
- `external_probe_combo`: probes account externals via `BALANCE`/`EXT*` opcodes
- `call_family_accumulate`: runs call-family opcodes and accumulates success flags
- `create_create2_selfdestruct`: runs create opcodes and terminates with `SELFDESTRUCT`

Example runner:

```bash
zig build examples -- adder storage_roundtrip
```

## Supported Opcodes

- `0x00` `STOP`
- `0x01` `ADD`
- `0x02` `MUL`
- `0x03` `SUB`
- `0x04` `DIV`
- `0x05` `SDIV`
- `0x06` `MOD`
- `0x07` `SMOD`
- `0x08` `ADDMOD`
- `0x09` `MULMOD`
- `0x0A` `EXP`
- `0x0B` `SIGNEXTEND`
- `0x10` `LT`
- `0x11` `GT`
- `0x12` `SLT`
- `0x13` `SGT`
- `0x14` `EQ`
- `0x15` `ISZERO`
- `0x16` `AND`
- `0x17` `OR`
- `0x18` `XOR`
- `0x19` `NOT`
- `0x1A` `BYTE`
- `0x1B` `SHL`
- `0x1C` `SHR`
- `0x1D` `SAR`
- `0x20` `SHA3`
- `0x30` `ADDRESS`
- `0x31` `BALANCE`
- `0x32` `ORIGIN`
- `0x33` `CALLER`
- `0x34` `CALLVALUE`
- `0x35` `CALLDATALOAD`
- `0x36` `CALLDATASIZE`
- `0x37` `CALLDATACOPY`
- `0x38` `CODESIZE`
- `0x39` `CODECOPY`
- `0x3A` `GASPRICE`
- `0x3B` `EXTCODESIZE`
- `0x3C` `EXTCODECOPY`
- `0x3D` `RETURNDATASIZE`
- `0x3E` `RETURNDATACOPY`
- `0x3F` `EXTCODEHASH`
- `0x40` `BLOCKHASH`
- `0x41` `COINBASE`
- `0x42` `TIMESTAMP`
- `0x43` `NUMBER`
- `0x44` `PREVRANDAO`
- `0x45` `GASLIMIT`
- `0x46` `CHAINID`
- `0x47` `SELFBALANCE`
- `0x48` `BASEFEE`
- `0x50` `POP`
- `0x51` `MLOAD`
- `0x52` `MSTORE`
- `0x53` `MSTORE8`
- `0x54` `SLOAD`
- `0x55` `SSTORE`
- `0x56` `JUMP`
- `0x57` `JUMPI`
- `0x58` `PC`
- `0x59` `MSIZE`
- `0x5A` `GAS`
- `0x5B` `JUMPDEST`
- `0x5F` `PUSH0`
- `0xA0` to `0xA4` `LOG0` to `LOG4`
- `0x60` to `0x7F` `PUSH1` to `PUSH32`
- `0x80` to `0x8F` `DUP1` to `DUP16`
- `0x90` to `0x9F` `SWAP1` to `SWAP16`
- `0xF0` `CREATE`
- `0xF1` `CALL`
- `0xF2` `CALLCODE`
- `0xF3` `RETURN`
- `0xF4` `DELEGATECALL`
- `0xF5` `CREATE2`
- `0xFA` `STATICCALL`
- `0xFD` `REVERT`
- `0xFF` `SELFDESTRUCT`

## Gas Model (Current)

- `STOP`: `0`
- `PUSH0`: `2`
- `PUSH1`..`PUSH32`: `3`
- `POP`: `2`
- `DUP1`..`DUP16`: `3`
- `SWAP1`..`SWAP16`: `3`
- `ADD`, `SUB`: `3`
- `LT`, `GT`, `SLT`, `SGT`, `EQ`, `ISZERO`: `3`
- `AND`, `OR`, `XOR`, `NOT`, `BYTE`: `3`
- `SHL`, `SHR`, `SAR`: `3`
- `MUL`, `DIV`, `SDIV`, `MOD`, `SMOD`: `5`
- `SIGNEXTEND`: `5`
- `ADDMOD`, `MULMOD`: `8`
- `EXP`: `10 + 50 * significant_exponent_bytes`
- `SHA3`: `30 + 6 * words`
- `ADDRESS`, `ORIGIN`, `CALLER`, `CALLVALUE`: `2`
- `BALANCE`: `100` warm, `2600` cold first access (`100 + 2500` surcharge)
- `CALLDATALOAD`: `3`
- `CALLDATASIZE`: `2`
- `CALLDATACOPY`: `3 + 3 * words`
- `CODESIZE`: `2`
- `CODECOPY`: `3 + 3 * words`
- `GASPRICE`: `2`
- `EXTCODESIZE`, `EXTCODEHASH`: `100` warm, `2600` cold first access
- `EXTCODECOPY`: `100 + 3 * words` warm, plus `2500` cold surcharge on first access
- `RETURNDATASIZE`: `2`
- `RETURNDATACOPY`: `3 + 3 * words`
- `BLOCKHASH`: `20`
- `COINBASE`, `TIMESTAMP`, `NUMBER`, `PREVRANDAO`, `GASLIMIT`, `CHAINID`: `2`
- `SELFBALANCE`: `5`
- `BASEFEE`: `2`
- `MLOAD`, `MSTORE`, `MSTORE8`: `3`
- `JUMP`: `8`
- `JUMPI`: `10`
- `PC`, `MSIZE`, `GAS`: `2`
- `JUMPDEST`: `1`
- `SLOAD`: dynamic (`100` warm / `2100` cold)
- `SSTORE`: Berlin-style dynamic pricing + refund counter (capped at one-fifth gas used on success)
- `LOGn`: `375 + n * 375 + data_size * 8`
- `CREATE`: `32000 + 2 * words(init_code)`
- `CREATE2`: `32000 + 2 * words(init_code) + 6 * words(init_code)`
- `CALL`, `CALLCODE`, `DELEGATECALL`, `STATICCALL`: `700`
- `RETURN`, `REVERT`: `0` (memory expansion still applies)
- `SELFDESTRUCT`: `5000`
- memory expansion: additional charged by word growth

`CREATE`/`CREATE2` execute init code in a child frame, deploy returned runtime bytecode on
success, and push the created address (or `0` on recoverable failure). `CALL`/`CALLCODE`/
`DELEGATECALL`/`STATICCALL` execute child frames, return `1`/`0` success flags, and expose
child returndata via `RETURNDATA*`. `CALL` value transfers update balances on success,
`STATICCALL` enforces no state writes, and `SELFDESTRUCT` transfers balance to its beneficiary.
Forwarded call gas is capped by the EIP-150 63/64 rule, and value-bearing `CALL`/`CALLCODE`
receive the 2300 gas stipend.
For `CREATE`/`CREATE2`, returndata is cleared on success and preserved on failure.
Deployment is rejected when runtime code starts with `0xef`, exceeds max code size,
or code-deposit gas cannot be paid.

## Project Layout

- `src/main.c`: CLI entrypoint
- `src/evm.c`: VM execution, gas, memory/storage/log handling
- `src/stack.c`: fixed-depth stack implementation
- `src/uint256.c`: 256-bit integer operations
- `include/*.h`: public headers and opcode constants
- `tests/test_suite.c`: unit and behavior tests

## Acknowledgements

- The Ethereum ecosystem and specifications for EVM opcode behavior and execution model guidance.
- Gavin Wood's Ethereum Yellow Paper: [`Ethereum: A Secure Decentralised Generalised Transaction Ledger`](https://ethereum.github.io/yellowpaper/paper.pdf).
- [`evm.codes`](https://www.evm.codes/) as a practical opcode reference during implementation and testing.
- `src/keccak.c` attribution: Pawel Bylica (`ethash` Keccak implementation, Apache-2.0) and Ronny Van Keer (Keccak-f[1600] reference implementation, CC0/Public Domain).
- The maintainers of OpenSSL (`libcrypto`), `libsecp256k1`, GMP, and BLAKE2 (`libb2`) used by this project.
