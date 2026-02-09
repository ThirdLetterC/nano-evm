#ifndef NANOSOL_COMMON_INTERNAL_H
#define NANOSOL_COMMON_INTERNAL_H

#include "nanosol/internal.h"
#include "opcodes.h"

const char *token_invalid_message(const NanoSol_Token *token);
NanoSol_Token lexer_next_token(NanoSol_Lexer *lexer);

void compiler_set_error(NanoSol_Compiler *compiler, NanoSol_Status status,
                        const NanoSol_Token *token, const char *fmt, ...);

bool compiler_emit_opcode(NanoSol_Compiler *compiler, uint8_t opcode);
bool compiler_emit_push_u64(NanoSol_Compiler *compiler, uint64_t value);
bool compiler_emit_push_size(NanoSol_Compiler *compiler, size_t value);
bool compiler_emit_store_current_frame_slot(NanoSol_Compiler *compiler,
                                            size_t slot_offset);
bool compiler_emit_load_current_frame_slot(NanoSol_Compiler *compiler,
                                           size_t slot_offset);
bool compiler_emit_allocate_call_frame(NanoSol_Compiler *compiler);

void compiler_pop_locals_to_scope_depth(NanoSol_Compiler *compiler,
                                        size_t max_scope_depth);
void compiler_clear_locals(NanoSol_Compiler *compiler);
ptrdiff_t compiler_find_local(const NanoSol_Compiler *compiler,
                              const NanoSol_Token *token);
bool compiler_add_local(NanoSol_Compiler *compiler,
                        const NanoSol_Token *name_token);

ptrdiff_t compiler_find_function(const NanoSol_Compiler *compiler,
                                 const NanoSol_Token *token);
ptrdiff_t compiler_find_function_literal(const NanoSol_Compiler *compiler,
                                         const char *name);
bool compiler_add_function_declaration(NanoSol_Compiler *compiler,
                                       const NanoSol_Token *name_token,
                                       size_t parameter_count);

size_t compiler_new_label(NanoSol_Compiler *compiler);
bool compiler_mark_label(NanoSol_Compiler *compiler, size_t label_index);
bool compiler_emit_push_label(NanoSol_Compiler *compiler, size_t label_index);
bool compiler_emit_jump(NanoSol_Compiler *compiler, size_t label_index,
                        bool conditional);
bool compiler_patch_labels(NanoSol_Compiler *compiler);

bool compiler_match(NanoSol_Compiler *compiler, NanoSol_TokenKind kind);
bool compiler_expect(NanoSol_Compiler *compiler, NanoSol_TokenKind kind,
                     const char *message);
bool compiler_identifier_equals(const NanoSol_Compiler *compiler,
                               const NanoSol_Token *token,
                               const char *literal);
bool compiler_emit_booleanize_top(NanoSol_Compiler *compiler);
bool compiler_parse_expression(NanoSol_Compiler *compiler);

const NanoSol_BuiltinSpec *
compiler_find_expression_builtin(const NanoSol_Compiler *compiler,
                                 const NanoSol_Token *name);
bool compiler_emit_reverse_argument_order(NanoSol_Compiler *compiler,
                                          size_t arity);
bool compiler_parse_call_arguments(NanoSol_Compiler *compiler,
                                   size_t *out_argument_count);
bool compiler_emit_push_numeric_literal(NanoSol_Compiler *compiler,
                                        const NanoSol_Token *token);

bool compiler_emit_user_function_call(NanoSol_Compiler *compiler,
                                      const NanoSol_Token *call_name,
                                      size_t function_index,
                                      size_t argument_count,
                                      bool discard_result);
bool compiler_emit_internal_function_return(NanoSol_Compiler *compiler);
bool compiler_emit_external_word_return(NanoSol_Compiler *compiler);

#endif
