#pragma once
#include <stdint.h>

#define EXPR_JIT_COMPILER_MSVC		(0)
#define EXPR_JIT_COMPILER_CLANG		(0)
#define EXPR_JIT_COMPILER_GCC		(0)

#if defined(__clang__)
	#undef EXPR_JIT_COMPILER_CLANG
	#define EXPR_JIT_COMPILER_CLANG (1)
#elif defined(__GNUG__)
	#undef EXPR_JIT_COMPILER_GCC	
	#define EXPR_JIT_COMPILER_GCC	(1)
#elif defined(_MSC_VER)
	#undef EXPR_JIT_COMPILER_MSVC
	#define EXPR_JIT_COMPILER_MSVC	(1)
#else
	#error Compiler could not be detected.
#endif

#if (EXPR_JIT_COMPILER_CLANG || EXPR_JIT_COMPILER_GCC)
	#define EXPR_JIT_UNREACHABLE __builtin_unreachable();
#elif EXPR_JIT_COMPILER_MSVC
	#define EXPR_JIT_UNREACHABLE __assume(0);
#else
	#error Compiler not supported.
#endif

#ifndef EXPR_JIT_ASSERT
	#include <assert.h>
	#define EXPR_JIT_ASSERT(_expr) assert((_expr))
#endif


namespace expr_jit
{

using error_cb = void(*)(char const* _err_str);

using alloc_fn = void*(*)(void* _ctx, size_t _size);
using free_fn = void(*)(void* _ctx, void* _ptr);

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

// Jit expression to x64. Returns amount of bytes that were written, or would have been if _buff_size was too small.
uint32_t jit_expr_x64(expr const* _expr, uint8_t* _buff, size_t _buff_size);

// Size in bytes needed to jit this expression.
uint32_t jit_expr_x64_size(expr const* _expr);

inline float expr_jit_eval(void const* _code_ptr, float const* _args)
{
	using expr_fn = float(*)(float const* _args);
	return (expr_fn(_code_ptr))(_args);
}

// Evaluate expression by walking the AST.
float expr_eval(expr const* _expr, float const* _args);

// Returns whether the expression is constant.
bool is_expr_constant(expr const* _expr);

} // namespace expr_jit