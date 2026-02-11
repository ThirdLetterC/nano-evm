default:
    @just --list

build:
    zig build

clean:
    rm -rf zig-out .zig-cache

format:
    find include src tests -type f \( -name '*.h' -o -name '*.c' \) -print0 | xargs -0 -r clang-format -i

test:
    zig build test

examples:
    zig build examples

solc:
    zig build solc

node:
    zig build node

debug:
    zig build debug

test-debug:
    zig build test-debug

fuzz:
    zig build fuzz

fuzz-debug:
    zig build fuzz-debug

fuzz-hex *inputs:
    zig build fuzz-hex -- {{inputs}}

fuzz-nanosol *inputs:
    zig build fuzz-nanosol -- {{inputs}}

fuzz-node-state *inputs:
    zig build fuzz-node-state -- {{inputs}}

run bytecode gas='100000':
    zig build
    zig-out/bin/nano-evm {{bytecode}} {{gas}}

compile source:
    zig build solc
    zig-out/bin/nano-solc {{source}}

compile-run source gas='100000':
    zig build solc
    zig-out/bin/nano-solc {{source}} --run {{gas}}
