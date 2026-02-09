#include "stack.h"

void stack_init(EVM_Stack *stack) { stack->top = 0; }

StackResult stack_push(EVM_Stack *stack, const uint256_t *value) {
  if (stack->top >= EVM_STACK_MAX_DEPTH) {
    return STACK_OVERFLOW;
  }
  stack->data[stack->top++] = *value;
  return STACK_OK;
}

StackResult stack_pop(EVM_Stack *stack, uint256_t *out) {
  if (stack->top == 0) {
    return STACK_UNDERFLOW;
  }
  *out = stack->data[--stack->top];
  return STACK_OK;
}

StackResult stack_peek(const EVM_Stack *stack, uint256_t *out) {
  if (stack->top == 0) {
    return STACK_UNDERFLOW;
  }
  *out = stack->data[stack->top - 1];
  return STACK_OK;
}

size_t stack_depth(const EVM_Stack *stack) { return stack->top; }
