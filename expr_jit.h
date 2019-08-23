#pragma once
#include <stdint.h>

namespace expr_jit
{

using error_cb = void(*)(char const* _err_str);

using alloc_fn = void*(*)(void* _ctx, size_t _size);
using free_fn = void(*)(void* _ctx, void* _ptr);

using asm_write_fn = void(*)(void* _ctx, void const* _asm_ptr, uint32_t _size);

struct expr;

struct expression_info
{
	char const* expr;
	uint32_t expr_len;

	char const* const* variables;
	uint32_t num_variables;

	char const* const* constant_names;
	float const* constant_values;
	uint32_t num_constants;
};

struct alloc_hooks
{
	void* ctx;
	alloc_fn alloc;
	free_fn free;
};

expr* parse_expression(expression_info const& _info, error_cb _error_cb = nullptr, alloc_hooks* _alloc_hooks = nullptr);
void free_expression(expr* _expr);

void jit_expr_x64(expr const* _expr, asm_write_fn _write_cb, void* _write_ctx);

// Size in bytes needed to jit this expression.
uint32_t jit_expr_x64_size(expr const* _expr);

inline float expr_jit_eval(void const* _code_ptr, float const* _args)
{
	using expr_fn = float(*)(float const* _args);
	return (expr_fn(_code_ptr))(_args);
}

} // namespace expr_jit