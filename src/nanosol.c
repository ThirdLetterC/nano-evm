// Shared compiler types, lexer, emit helpers, and patch/link machinery.
#include "nanosol/common.c"

// Expression grammar, function calls, and expression bytecode emission.
#include "nanosol/expression.c"

// Statement grammar and block/function-body statement lowering.
#include "nanosol/statement.c"

// Top-level program parsing and compiler lifecycle internals.
#include "nanosol/program.c"

// Public NanoSol compile APIs and status string helpers.
#include "nanosol/api.c"
