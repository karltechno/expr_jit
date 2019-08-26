#include <string.h>
#include <stdio.h>
#include <math.h>
#include <algorithm>

#include "expr_jit.h"
#include "utest.h"

UTEST_STATE();

void* g_code_ptr = nullptr;
uint32_t constexpr c_code_ptr_size = 4096 * 4;

static bool float_rel_equal(float _lhs, float _rhs, float _minAbs, float _relTol)
{
	float const tol = std::max(_minAbs, std::max(fabsf(_lhs), fabsf(_rhs)) * _relTol);
	return fabsf(_lhs - _rhs) <= tol;
}

void* alloc_writeable_executable_page()
{
	void* p = ::VirtualAlloc(nullptr, c_code_ptr_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	DWORD oldprotect;
	::VirtualProtect(p, c_code_ptr_size, PAGE_EXECUTE_READWRITE, &oldprotect);
	return p;
}

#define JIT_AND_RUN(_expr, _args, _val) \
{ \
	uint32_t const code_size = expr_jit::jit_expr_x64(_expr, g_code_ptr, c_code_ptr_size); \
	ASSERT_TRUE(code_size <= c_code_ptr_size); \
	_val = expr_jit::expr_jit_eval(g_code_ptr, _args); \
}

UTEST(constant_fold, fold1)
{
	expr_jit::expression_info info = {};
	info.expr = "2 * (4 + -2*6)";
	info.expr_len = uint32_t(strlen(info.expr));

	expr_jit::expr* expr = expr_jit::parse_expression(info, [](char const* _err) { printf(_err); });
	ASSERT_TRUE(expr);
	ASSERT_TRUE(expr_jit::is_expr_constant(expr));

	float const expected = -16.0f;

	float jit_val;
	JIT_AND_RUN(expr, nullptr, jit_val);

	ASSERT_TRUE(expr_jit::expr_eval(expr, nullptr) == expected);
	ASSERT_TRUE(jit_val == expected);

	expr_jit::free_expression(expr);
}

UTEST(constant_fold, fold2)
{
	expr_jit::expression_info info = {};
	info.expr = "1 + 2 + 3 + 4 + 5 + 6 + 7 + 8 + 9 + 10";
	info.expr_len = uint32_t(strlen(info.expr));

	expr_jit::expr* expr = expr_jit::parse_expression(info, [](char const* _err) { printf(_err); });
	ASSERT_TRUE(expr);
	ASSERT_TRUE(expr_jit::is_expr_constant(expr));

	float const expected = 55.0f;
	float jit_val;
	JIT_AND_RUN(expr, nullptr, jit_val);

	ASSERT_TRUE(expr_jit::expr_eval(expr, nullptr) == expected);
	ASSERT_TRUE(jit_val == expected);
	expr_jit::free_expression(expr);
}

UTEST(constant_fold, fold3)
{
	expr_jit::expression_info info = {};
	info.expr = "1 + -1 + 3 + -3 + 4 + -4 + 5 + -5";
	info.expr_len = uint32_t(strlen(info.expr));

	expr_jit::expr* expr = expr_jit::parse_expression(info, [](char const* _err) { printf(_err); });
	ASSERT_TRUE(expr);
	ASSERT_TRUE(expr_jit::is_expr_constant(expr));

	float jit_val;
	JIT_AND_RUN(expr, nullptr, jit_val);

	ASSERT_TRUE(expr_jit::expr_eval(expr, nullptr) == 0.0f);
	ASSERT_TRUE(jit_val == 0.0f);
	expr_jit::free_expression(expr);
}

UTEST(generic_expr, expr1)
{
	expr_jit::expression_info info = {};
	info.expr = "1 + 2 + 3 + 4 + x + 6 + 7 + 8 + 9 + 10";
	info.expr_len = uint32_t(strlen(info.expr));

	char const* arg_names[] = { "x" };
	info.variables = arg_names;
	info.num_variables = sizeof(arg_names) / sizeof(*arg_names);

	expr_jit::expr* expr = expr_jit::parse_expression(info, [](char const* _err) { printf(_err); });
	ASSERT_TRUE(expr);
	ASSERT_FALSE(expr_jit::is_expr_constant(expr));

	float args[] = { 5.0f };

	float jit_val;
	JIT_AND_RUN(expr, args, jit_val);

	ASSERT_TRUE(expr_jit::expr_eval(expr, args) == 55.0f);
	ASSERT_TRUE(jit_val == 55.0f);

	expr_jit::free_expression(expr);
}



UTEST(generic_expr, expr2)
{
	expr_jit::expression_info info = {};
	info.expr = "(( (x + 1) * (-y / 2) ) * (z + 1))";
	info.expr_len = uint32_t(strlen(info.expr));

	char const* arg_names[] = { "x", "y", "z" };
	info.variables = arg_names;
	info.num_variables = sizeof(arg_names) / sizeof(*arg_names);

	expr_jit::expr* expr = expr_jit::parse_expression(info, [](char const* _err) { printf(_err); });
	ASSERT_TRUE(expr);
	ASSERT_FALSE(expr_jit::is_expr_constant(expr));

	float args[] = { 5.0f, 2.0f, 3.0f };

	float jit_val;
	JIT_AND_RUN(expr, args, jit_val);

	float const val_real = (((args[0] + 1.0f) * (-args[1] / 2.0f)) * (args[2] + 1.0f));

	ASSERT_TRUE(expr_jit::expr_eval(expr, args) == val_real);
	ASSERT_TRUE(val_real == jit_val);
	expr_jit::free_expression(expr);
}

UTEST(generic_expr, expr3)
{
	expr_jit::expression_info info = {};
	info.expr = "(((x + 1) * (-y / 2) ) * (z + 1)) * (y / x * 0.5) / (z*-x + 2)";
	info.expr_len = uint32_t(strlen(info.expr));

	char const* arg_names[] = { "x", "y", "z" };
	info.variables = arg_names;
	info.num_variables = sizeof(arg_names) / sizeof(*arg_names);

	expr_jit::expr* expr = expr_jit::parse_expression(info, [](char const* _err) { printf(_err); });
	ASSERT_TRUE(expr);
	ASSERT_FALSE(expr_jit::is_expr_constant(expr));

	float args[] = { 5.0f, 2.0f, 3.0f };

	float jit_val;
	JIT_AND_RUN(expr, args, jit_val);

	float const val_real = (((args[0] + 1.0f) * (-args[1] / 2.0f)) * (args[2] + 1.0f)) * (args[1] / args[0] * 0.5f) / (args[2]*-args[0] + 2.0f);

	ASSERT_TRUE(expr_jit::expr_eval(expr, args) == val_real);
	ASSERT_TRUE(val_real == jit_val);
	expr_jit::free_expression(expr);
}

UTEST(generic_expr, expr4)
{
	expr_jit::expression_info info = {};
	info.expr = "x + 1 + 2 + 3 + 4 + 6 + 7 + 8 + 9 + 10 + (y * 3 * 4 * 5 * 6 * 1)";
	info.expr_len = uint32_t(strlen(info.expr));

	char const* arg_names[] = { "x", "y" };
	info.variables = arg_names;
	info.num_variables = sizeof(arg_names) / sizeof(*arg_names);

	expr_jit::expr* expr = expr_jit::parse_expression(info, [](char const* _err) { printf(_err); });
	ASSERT_TRUE(expr);
	ASSERT_FALSE(expr_jit::is_expr_constant(expr));

	float args[] = { 5.0f, 1.5f };

	float const real_val = args[0] + 1.0f + 2.0f + 3.0f + 4.0f + 6.0f + 7.0f + 8.0f + 9.0f + 10.0f + (args[1] * 3.0f * 4.0f * 5.0f * 6.0f);

	float jit_val;
	JIT_AND_RUN(expr, args, jit_val);

	ASSERT_TRUE(expr_jit::expr_eval(expr, args) == real_val);
	ASSERT_TRUE(jit_val == real_val);

	expr_jit::free_expression(expr);
}


UTEST(functions, sqrt)
{
	expr_jit::expression_info info = {};
	info.expr = "sqrt(x)";
	info.expr_len = uint32_t(strlen(info.expr));

	char const* arg_names[] = { "x" };
	info.variables = arg_names;
	info.num_variables = sizeof(arg_names) / sizeof(*arg_names);

	expr_jit::expr* expr = expr_jit::parse_expression(info, [](char const* _err) { printf(_err); });
	ASSERT_TRUE(expr);
	ASSERT_FALSE(expr_jit::is_expr_constant(expr));

	{
		float const expected = 4.0f;

		float args[] = { 16.0f };

		float jit_val;
		JIT_AND_RUN(expr, args, jit_val);

		ASSERT_TRUE(expr_jit::expr_eval(expr, args) == expected);
		ASSERT_TRUE(jit_val == expected);
	}

	{
		float const expected = 8.0f;

		float args[] = { 64.0f };

		float jit_val;
		JIT_AND_RUN(expr, args, jit_val);

		ASSERT_TRUE(expr_jit::expr_eval(expr, args) == expected);
		ASSERT_TRUE(jit_val == expected);
	}


	expr_jit::free_expression(expr);
}

UTEST(functions, min)
{
	expr_jit::expression_info info = {};
	info.expr = "min(x, y)";
	info.expr_len = uint32_t(strlen(info.expr));

	char const* arg_names[] = { "x", "y" };
	info.variables = arg_names;
	info.num_variables = sizeof(arg_names) / sizeof(*arg_names);

	expr_jit::expr* expr = expr_jit::parse_expression(info, [](char const* _err) { printf(_err); });
	ASSERT_TRUE(expr);
	ASSERT_FALSE(expr_jit::is_expr_constant(expr));

	{
		float const expected = 4.0f;

		float args[] = { 16.0f, 4.0f };

		float jit_val;
		JIT_AND_RUN(expr, args, jit_val);

		ASSERT_TRUE(expr_jit::expr_eval(expr, args) == expected);
		ASSERT_TRUE(jit_val == expected);
	}

	{
		float const expected = -2.0f;

		float args[] = { 64.0f, -2.0f };

		float jit_val;
		JIT_AND_RUN(expr, args, jit_val);

		ASSERT_TRUE(expr_jit::expr_eval(expr, args) == expected);
		ASSERT_TRUE(jit_val == expected);
	}


	expr_jit::free_expression(expr);
}

UTEST(functions, max)
{
	expr_jit::expression_info info = {};
	info.expr = "max(x, y)";
	info.expr_len = uint32_t(strlen(info.expr));

	char const* arg_names[] = { "x", "y" };
	info.variables = arg_names;
	info.num_variables = sizeof(arg_names) / sizeof(*arg_names);

	expr_jit::expr* expr = expr_jit::parse_expression(info, [](char const* _err) { printf(_err); });
	ASSERT_TRUE(expr);
	ASSERT_FALSE(expr_jit::is_expr_constant(expr));

	{
		float const expected = 16.0f;

		float args[] = { 16.0f, 4.0f };

		float jit_val;
		JIT_AND_RUN(expr, args, jit_val);

		ASSERT_TRUE(expr_jit::expr_eval(expr, args) == expected);
		ASSERT_TRUE(jit_val == expected);
	}

	{
		float const expected = 64.0f;

		float args[] = { 64.0f, -2.0f };

		float jit_val;
		JIT_AND_RUN(expr, args, jit_val);

		ASSERT_TRUE(expr_jit::expr_eval(expr, args) == expected);
		ASSERT_TRUE(jit_val == expected);
	}


	expr_jit::free_expression(expr);
}

UTEST(functions, clamp)
{
	expr_jit::expression_info info = {};
	info.expr = "clamp(x, y, z)";
	info.expr_len = uint32_t(strlen(info.expr));

	char const* arg_names[] = { "x", "y", "z" };
	info.variables = arg_names;
	info.num_variables = sizeof(arg_names) / sizeof(*arg_names);

	expr_jit::expr* expr = expr_jit::parse_expression(info, [](char const* _err) { printf(_err); });
	ASSERT_TRUE(expr);
	ASSERT_FALSE(expr_jit::is_expr_constant(expr));

	{
		float const expected = 4.0f;

		float args[] = { 0.0f, 4.0f, 7.0f };

		float jit_val;
		JIT_AND_RUN(expr, args, jit_val);

		ASSERT_TRUE(expr_jit::expr_eval(expr, args) == expected);
		ASSERT_TRUE(jit_val == expected);
	}

	{
		float const expected = 0.5f;

		float args[] = { 0.5f, 0.45f, 1.0f};

		float jit_val;
		JIT_AND_RUN(expr, args, jit_val);

		ASSERT_TRUE(expr_jit::expr_eval(expr, args) == expected);
		ASSERT_TRUE(jit_val == expected);
	}


	expr_jit::free_expression(expr);
}

UTEST(functions, sqrt_xpow2)
{
	expr_jit::expression_info info = {};
	info.expr = "sqrt(x*x)";
	info.expr_len = uint32_t(strlen(info.expr));

	char const* arg_names[] = { "x" };
	info.variables = arg_names;
	info.num_variables = sizeof(arg_names) / sizeof(*arg_names);

	expr_jit::expr* expr = expr_jit::parse_expression(info, [](char const* _err) { printf(_err); });
	ASSERT_TRUE(expr);
	ASSERT_FALSE(expr_jit::is_expr_constant(expr));

	{
		float const expected = 4.0f;

		float args[] = { expected };

		float jit_val;
		JIT_AND_RUN(expr, args, jit_val);

		ASSERT_TRUE(expr_jit::expr_eval(expr, args) == expected);
		ASSERT_TRUE(jit_val == expected);
	}

	{
		float const expected = 8.0f;

		float args[] = { expected };

		float jit_val;
		JIT_AND_RUN(expr, args, jit_val);

		ASSERT_TRUE(expr_jit::expr_eval(expr, args) == expected);
		ASSERT_TRUE(jit_val == expected);
	}


	expr_jit::free_expression(expr);
}

UTEST(functions, sqrt_absxpow2)
{
	expr_jit::expression_info info = {};
	info.expr = "sqrt(abs(-(x*x)))";
	info.expr_len = uint32_t(strlen(info.expr));

	char const* arg_names[] = { "x" };
	info.variables = arg_names;
	info.num_variables = sizeof(arg_names) / sizeof(*arg_names);

	expr_jit::expr* expr = expr_jit::parse_expression(info, [](char const* _err) { printf(_err); });
	ASSERT_TRUE(expr);
	ASSERT_FALSE(expr_jit::is_expr_constant(expr));

	{
		float const expected = 4.0f;

		float args[] = { -expected };

		float jit_val;
		JIT_AND_RUN(expr, args, jit_val);

		ASSERT_TRUE(expr_jit::expr_eval(expr, args) == expected);
		ASSERT_TRUE(jit_val == expected);
	}

	{
		float const expected = 8.0f;

		float args[] = { -expected };

		float jit_val;
		JIT_AND_RUN(expr, args, jit_val);

		ASSERT_TRUE(expr_jit::expr_eval(expr, args) == expected);
		ASSERT_TRUE(jit_val == expected);
	}


	expr_jit::free_expression(expr);
}


UTEST(functions, constant_fold1)
{
	expr_jit::expression_info info = {};
	info.expr = "sqrt(min(abs(-(2*2)), 100))";
	info.expr_len = uint32_t(strlen(info.expr));

	expr_jit::expr* expr = expr_jit::parse_expression(info, [](char const* _err) { printf(_err); });
	ASSERT_TRUE(expr);
	ASSERT_TRUE(expr_jit::is_expr_constant(expr));

	float const expected = 2.0f;

	float jit_val;
	JIT_AND_RUN(expr, nullptr, jit_val);

	ASSERT_TRUE(expr_jit::expr_eval(expr, nullptr) == expected);
	ASSERT_TRUE(jit_val == expected);


	expr_jit::free_expression(expr);
}

int main(int argc, char** argv)
{
	g_code_ptr = alloc_writeable_executable_page();
	return utest_main(argc, argv);
}