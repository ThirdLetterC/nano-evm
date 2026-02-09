#ifndef STACK_H
#define STACK_H

#include <stddef.h>

#include "uint256.h"

static constexpr size_t EVM_STACK_MAX_DEPTH = 1'024;

typedef enum { STACK_OK = 0, STACK_OVERFLOW, STACK_UNDERFLOW } StackResult;

typedef struct {
  uint256_t data[EVM_STACK_MAX_DEPTH];
  size_t top;
} EVM_Stack;

void stack_init(EVM_Stack *stack);
[[nodiscard]] StackResult stack_push(EVM_Stack *stack, const uint256_t *value);
[[nodiscard]] StackResult stack_pop(EVM_Stack *stack, uint256_t *out);
[[nodiscard]] StackResult stack_peek(const EVM_Stack *stack, uint256_t *out);
[[nodiscard]] size_t stack_depth(const EVM_Stack *stack);

#endif
