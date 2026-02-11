# Security Model

This project treats all externally supplied data as untrusted:

- EVM bytecode and calldata (`nano-evm`, `nano-node call`)
- persisted node state files (`nano-node --state`)
- NanoSol source code (`nano-solc`, `nano-node deploy --source`)

## Threat Model

### Protected Assets

- process memory safety and control-flow integrity
- deterministic VM state transitions and gas accounting
- on-disk node state integrity

### Trust Boundaries

- CLI arguments and file contents cross from untrusted input into parser/VM code
- runtime account/storage snapshots cross frame boundaries during CALL/CREATE
- precompile input buffers cross from contract-controlled memory into crypto code

### Attacker Capabilities

- provide malformed or oversized hex/source/state inputs
- craft bytecode/calldata to stress parser and memory expansion paths
- trigger repeated state merges/clones to exercise allocation and bounds behavior

## Security Controls

### Validation and Bounds

- explicit max limits for node state file size, bytecode size, and table counts
- strict parser rejection for malformed hex, numeric literals, and state headers
- bounds-checked memory growth and copy helpers in VM execution paths

### Checked Arithmetic

- overflow-safe helpers (`add_size_overflow`, `mul_size_overflow`,
  `add_u64_overflow`, `mul_u64_overflow`) gate offset, size, and gas math
- `stdckdint` support is used when available, with safe fallbacks otherwise
- array clone/copy paths validate `count * sizeof(T)` before allocation/copy

### Fail-Secure Behavior

- validation failures return explicit error codes and stop execution
- partial merge/clone failures roll back intermediate allocations/state updates
- malformed internal state metadata is rejected rather than dereferenced

### Initialization and Ownership

- allocated buffers are zero-initialized via `calloc`
- ownership transfer paths reset moved pointers/counts to prevent double-free
- runtime account teardown clears owned code/storage/transient allocations

### Secrets Hygiene

- secret-like temporary buffers can be cleared with `nano_utils_secure_zero`
- no key material is persisted by node state serialization

### Toolchain Hardening

- C23 + warnings as errors (`-std=c23 -Wall -Wextra -Wpedantic -Werror`)
- hardening compile flags (`-fstack-protector-strong`, `-D_FORTIFY_SOURCE=3`,
  `-fPIE`)
- RELRO + NOW enabled in linker configuration
- sanitizer build targets available (`zig build debug`, `zig build test-debug`)

## Security Testing

- regression tests cover malformed state files and arithmetic overflow edges
- run baseline checks:

```bash
zig build test
zig build test-debug
```

- for parser and state machine hardening, fuzzing is recommended for:
  - hex parser (`evm_load_hex`)
  - NanoSol lexer/parser
  - node state file loader
