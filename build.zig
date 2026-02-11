const std = @import("std");

const release_cflags = &.{
    "-std=c23",
    "-Wall",
    "-Wextra",
    "-Wpedantic",
    "-Werror",
    "-Wformat",
    "-Wformat-security",
    "-fstack-protector-strong",
    "-fPIE",
    "-D_FORTIFY_SOURCE=3",
    "-DNANO_EVM_DISABLE_CPU_DISPATCH=1",
    "-O2",
};

const debug_cflags = &.{
    "-std=c23",
    "-Wall",
    "-Wextra",
    "-Wpedantic",
    "-Werror",
    "-Wformat",
    "-Wformat-security",
    "-fstack-protector-strong",
    "-fPIE",
    "-D_FORTIFY_SOURCE=3",
    "-DNANO_EVM_DISABLE_CPU_DISPATCH=1",
    "-O0",
    "-g3",
};

const app_sources = &.{
    "src/main.c",
    "src/evm.c",
    "src/evm/bn254_pairing.c",
    "src/stack.c",
    "src/uint256.c",
    "src/keccak.c",
    "src/contracts.c",
    "src/nanosol.c",
};

const solc_sources = &.{
    "src/nanosol_main.c",
    "src/evm.c",
    "src/evm/bn254_pairing.c",
    "src/stack.c",
    "src/uint256.c",
    "src/keccak.c",
    "src/nanosol.c",
};

const node_sources = &.{
    "src/nano_node.c",
    "src/evm.c",
    "src/evm/bn254_pairing.c",
    "src/stack.c",
    "src/uint256.c",
    "src/keccak.c",
    "src/nanosol.c",
};

const test_sources = &.{
    "tests/test_suite.c",
    "tests/test_helpers.c",
    "tests/test_arithmetic_and_stack.c",
    "tests/test_sub_underflow_wraps.c",
    "tests/test_div_by_zero_returns_zero.c",
    "tests/test_core_arithmetic_logic_opcodes.c",
    "tests/test_memory_ops.c",
    "tests/test_sha3_opcode.c",
    "tests/test_storage_ops.c",
    "tests/test_return_and_revert.c",
    "tests/test_sstore_refund_semantics.c",
    "tests/test_log_ops.c",
    "tests/test_contract_io_opcodes.c",
    "tests/test_high_value_low_complexity_opcodes.c",
    "tests/test_new_signed_and_transient_opcodes.c",
    "tests/test_new_context_external_and_copy_opcodes.c",
    "tests/test_new_call_create_and_selfdestruct_opcodes.c",
    "tests/test_precompile_dispatch.c",
    "tests/test_create2_increments_sender_nonce_for_create_addressing.c",
    "tests/test_call_frame_state_persistence.c",
    "tests/test_call_value_stipend_does_not_mint_gas.c",
    "tests/test_call_new_account_charge_for_empty_runtime_entry.c",
    "tests/test_modexp_adjusted_exponent_gas.c",
    "tests/test_out_of_gas.c",
    "tests/test_invalid_opcode_and_bytecode.c",
    "tests/test_memory_expansion_helper_cost.c",
    "tests/test_memory_expansion_overflow_is_runtime_error.c",
    "tests/test_bn254_pairing_api_input_validation.c",
    "tests/test_per_opcode_gas.c",
    "tests/test_api_and_error_surfaces.c",
    "tests/test_uint256_and_stack_helpers.c",
    "tests/test_stack_and_static_context_errors.c",
    "tests/test_execution_internal_and_depth_guards.c",
    "tests/test_hex_parser.c",
    "tests/test_contracts_module.c",
    "tests/test_nanosol_compiler_arithmetic_return.c",
    "tests/test_nanosol_compiler_control_flow_and_storage.c",
    "tests/test_nanosol_compiler_semantic_error.c",
    "tests/test_nanosol_compiler_numeric_literal_validation.c",
    "tests/test_nanosol_compiler_unterminated_block_comment.c",
    "tests/test_nanosol_cli_e2e.c",
    "tests/test_nano_node_state_file_validation.c",
    "tests/test_state_clone_overflow_guards.c",
    "src/evm.c",
    "src/evm/bn254_pairing.c",
    "src/stack.c",
    "src/uint256.c",
    "src/keccak.c",
    "src/contracts.c",
    "src/nanosol.c",
};

const example_sources = &.{
    "src/contracts_examples.c",
    "src/evm.c",
    "src/evm/bn254_pairing.c",
    "src/stack.c",
    "src/uint256.c",
    "src/keccak.c",
    "src/contracts.c",
    "src/nanosol.c",
};

const fuzz_hex_sources = &.{
    "tests/fuzz_hex_parser.c",
    "src/evm.c",
    "src/evm/bn254_pairing.c",
    "src/stack.c",
    "src/uint256.c",
    "src/keccak.c",
};

const fuzz_nanosol_sources = &.{
    "tests/fuzz_nanosol_parser.c",
    "src/evm.c",
    "src/evm/bn254_pairing.c",
    "src/stack.c",
    "src/uint256.c",
    "src/keccak.c",
    "src/nanosol.c",
};

const fuzz_node_state_sources = &.{
    "tests/fuzz_node_state_loader.c",
    "src/evm.c",
    "src/evm/bn254_pairing.c",
    "src/stack.c",
    "src/uint256.c",
    "src/keccak.c",
    "src/nanosol.c",
};

fn add_c_executable(
    b: *std.Build,
    name: []const u8,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    sanitize_c: ?std.zig.SanitizeC,
    sources: []const []const u8,
    cflags: []const []const u8,
) *std.Build.Step.Compile {
    const module = b.createModule(.{
        .target = target,
        .optimize = optimize,
        .link_libc = true,
        .sanitize_c = sanitize_c,
    });
    module.addIncludePath(b.path("include"));
    module.addCSourceFiles(.{
        .files = sources,
        .flags = cflags,
    });

    const exe = b.addExecutable(.{
        .name = name,
        .root_module = module,
    });
    add_hardening_linker_flags(exe, target);
    exe.linkSystemLibrary("crypto");
    exe.linkSystemLibrary("secp256k1");
    exe.linkSystemLibrary("gmp");
    exe.linkSystemLibrary("b2");
    return exe;
}

fn add_hardening_linker_flags(
    exe: *std.Build.Step.Compile,
    target: std.Build.ResolvedTarget,
) void {
    _ = target;
    exe.pie = true;
    exe.link_z_relro = true;
    exe.link_z_lazy = false;
}

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});

    const nano_evm = add_c_executable(
        b,
        "nano-evm",
        target,
        .Debug,
        null,
        app_sources,
        release_cflags,
    );
    b.installArtifact(nano_evm);

    const nano_solc = add_c_executable(
        b,
        "nano-solc",
        target,
        .Debug,
        null,
        solc_sources,
        release_cflags,
    );
    const install_solc = b.addInstallArtifact(nano_solc, .{});
    const solc_step = b.step("solc", "Build nano-solc");
    solc_step.dependOn(&install_solc.step);

    const nano_node = add_c_executable(
        b,
        "nano-node",
        target,
        .Debug,
        null,
        node_sources,
        release_cflags,
    );
    const install_node = b.addInstallArtifact(nano_node, .{});
    const node_step = b.step("node", "Build nano-node");
    node_step.dependOn(&install_node.step);

    const test_suite = add_c_executable(
        b,
        "test_suite",
        target,
        .Debug,
        null,
        test_sources,
        release_cflags,
    );
    const run_test_suite = b.addRunArtifact(test_suite);
    run_test_suite.step.dependOn(&install_solc.step);
    run_test_suite.setEnvironmentVariable(
        "NANO_SOLC_PATH",
        b.getInstallPath(.bin, "nano-solc"),
    );
    run_test_suite.setEnvironmentVariable(
        "NANO_NODE_PATH",
        b.getInstallPath(.bin, "nano-node"),
    );
    run_test_suite.step.dependOn(&install_node.step);
    if (b.args) |args| {
        run_test_suite.addArgs(args);
    }
    const test_step = b.step("test", "Build and run test suite");
    test_step.dependOn(&run_test_suite.step);

    const contract_examples = add_c_executable(
        b,
        "contract_examples",
        target,
        .Debug,
        null,
        example_sources,
        release_cflags,
    );
    const run_contract_examples = b.addRunArtifact(contract_examples);
    if (b.args) |args| {
        run_contract_examples.addArgs(args);
    }
    const examples_step = b.step("examples", "Build and run contract examples");
    examples_step.dependOn(&run_contract_examples.step);

    const fuzz_hex = add_c_executable(
        b,
        "fuzz_hex_parser",
        target,
        .Debug,
        null,
        fuzz_hex_sources,
        release_cflags,
    );
    const install_fuzz_hex = b.addInstallArtifact(fuzz_hex, .{});

    const fuzz_nanosol = add_c_executable(
        b,
        "fuzz_nanosol_parser",
        target,
        .Debug,
        null,
        fuzz_nanosol_sources,
        release_cflags,
    );
    const install_fuzz_nanosol = b.addInstallArtifact(fuzz_nanosol, .{});

    const fuzz_node_state = add_c_executable(
        b,
        "fuzz_node_state_loader",
        target,
        .Debug,
        null,
        fuzz_node_state_sources,
        release_cflags,
    );
    const install_fuzz_node_state = b.addInstallArtifact(fuzz_node_state, .{});

    const fuzz_build_step = b.step("fuzz", "Build fuzz harness binaries");
    fuzz_build_step.dependOn(&install_fuzz_hex.step);
    fuzz_build_step.dependOn(&install_fuzz_nanosol.step);
    fuzz_build_step.dependOn(&install_fuzz_node_state.step);

    const run_fuzz_hex = b.addRunArtifact(fuzz_hex);
    if (b.args) |args| {
        run_fuzz_hex.addArgs(args);
    }
    const fuzz_hex_step = b.step(
        "fuzz-hex",
        "Run hex parser fuzz harness over input files",
    );
    fuzz_hex_step.dependOn(&run_fuzz_hex.step);

    const run_fuzz_nanosol = b.addRunArtifact(fuzz_nanosol);
    if (b.args) |args| {
        run_fuzz_nanosol.addArgs(args);
    }
    const fuzz_nanosol_step = b.step(
        "fuzz-nanosol",
        "Run NanoSol parser/compiler fuzz harness over input files",
    );
    fuzz_nanosol_step.dependOn(&run_fuzz_nanosol.step);

    const run_fuzz_node_state = b.addRunArtifact(fuzz_node_state);
    if (b.args) |args| {
        run_fuzz_node_state.addArgs(args);
    }
    const fuzz_node_state_step = b.step(
        "fuzz-node-state",
        "Run node state loader fuzz harness over input files",
    );
    fuzz_node_state_step.dependOn(&run_fuzz_node_state.step);

    const nano_evm_release = add_c_executable(
        b,
        "nano-evm-release",
        target,
        .ReleaseFast,
        null,
        app_sources,
        release_cflags,
    );
    const install_release = b.addInstallArtifact(nano_evm_release, .{});
    const release_step = b.step("release", "Build nano-evm-release in release mode");
    release_step.dependOn(&install_release.step);

    const nano_evm_debug = add_c_executable(
        b,
        "nano-evm-debug",
        target,
        .Debug,
        .full,
        app_sources,
        debug_cflags,
    );
    const install_debug = b.addInstallArtifact(nano_evm_debug, .{});
    const debug_step = b.step("debug", "Build nano-evm-debug with sanitizers");
    debug_step.dependOn(&install_debug.step);

    const test_suite_debug = add_c_executable(
        b,
        "test_suite-debug",
        target,
        .Debug,
        .full,
        test_sources,
        debug_cflags,
    );
    const run_test_suite_debug = b.addRunArtifact(test_suite_debug);
    if (b.args) |args| {
        run_test_suite_debug.addArgs(args);
    }
    const test_debug_step = b.step("test-debug", "Build and run debug test suite");
    test_debug_step.dependOn(&run_test_suite_debug.step);

    const fuzz_hex_debug = add_c_executable(
        b,
        "fuzz_hex_parser-debug",
        target,
        .Debug,
        .full,
        fuzz_hex_sources,
        debug_cflags,
    );
    const install_fuzz_hex_debug = b.addInstallArtifact(fuzz_hex_debug, .{});

    const fuzz_nanosol_debug = add_c_executable(
        b,
        "fuzz_nanosol_parser-debug",
        target,
        .Debug,
        .full,
        fuzz_nanosol_sources,
        debug_cflags,
    );
    const install_fuzz_nanosol_debug = b.addInstallArtifact(fuzz_nanosol_debug, .{});

    const fuzz_node_state_debug = add_c_executable(
        b,
        "fuzz_node_state_loader-debug",
        target,
        .Debug,
        .full,
        fuzz_node_state_sources,
        debug_cflags,
    );
    const install_fuzz_node_state_debug = b.addInstallArtifact(fuzz_node_state_debug, .{});

    const fuzz_debug_step = b.step(
        "fuzz-debug",
        "Build sanitizer-enabled fuzz harness binaries",
    );
    fuzz_debug_step.dependOn(&install_fuzz_hex_debug.step);
    fuzz_debug_step.dependOn(&install_fuzz_nanosol_debug.step);
    fuzz_debug_step.dependOn(&install_fuzz_node_state_debug.step);

    const run_fuzz_hex_debug = b.addRunArtifact(fuzz_hex_debug);
    if (b.args) |args| {
        run_fuzz_hex_debug.addArgs(args);
    }
    const fuzz_hex_debug_step = b.step(
        "fuzz-hex-debug",
        "Run sanitizer hex parser fuzz harness over input files",
    );
    fuzz_hex_debug_step.dependOn(&run_fuzz_hex_debug.step);

    const run_fuzz_nanosol_debug = b.addRunArtifact(fuzz_nanosol_debug);
    if (b.args) |args| {
        run_fuzz_nanosol_debug.addArgs(args);
    }
    const fuzz_nanosol_debug_step = b.step(
        "fuzz-nanosol-debug",
        "Run sanitizer NanoSol parser/compiler fuzz harness over input files",
    );
    fuzz_nanosol_debug_step.dependOn(&run_fuzz_nanosol_debug.step);

    const run_fuzz_node_state_debug = b.addRunArtifact(fuzz_node_state_debug);
    if (b.args) |args| {
        run_fuzz_node_state_debug.addArgs(args);
    }
    const fuzz_node_state_debug_step = b.step(
        "fuzz-node-state-debug",
        "Run sanitizer node state loader fuzz harness over input files",
    );
    fuzz_node_state_debug_step.dependOn(&run_fuzz_node_state_debug.step);
}
