#include <string.h>
#include <stdio.h>
#include <math.h>
#include <algorithm>

#include "expr_jit.h"
#include "utest.h"

static bool float_rel_equal(float _lhs, float _rhs, float _minAbs, float _relTol)
{
	float const tol = std::max(_minAbs, std::max(fabsf(_lhs), fabsf(_rhs)) * _relTol);
	return fabsf(_lhs - _rhs) <= tol;
}

void* alloc_writeable_executable_page()
{
	void* p = ::VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	DWORD oldprotect;
	::VirtualProtect(p, 4096, PAGE_EXECUTE_READWRITE, &oldprotect);
	return p;
}

UTEST(constant_fold, fold1)
{
	expr_jit::expression_info info = {};
	info.expr = "2 * (4 + -2*6)";
	info.expr_len = uint32_t(strlen(info.expr));

	expr_jit::expr* expr = expr_jit::parse_expression(info, [](char const* _err) { printf(_err); });
	ASSERT_TRUE(expr);
	ASSERT_TRUE(expr_jit::is_expr_constant(expr));

	ASSERT_TRUE(expr_jit::expr_eval(expr, nullptr) == -16.0f);

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

	ASSERT_TRUE(expr_jit::expr_eval(expr, nullptr) == 55.0f);
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

	ASSERT_TRUE(expr_jit::expr_eval(expr, nullptr) == 0.0f);
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

	ASSERT_TRUE(expr_jit::expr_eval(expr, args) == 55.0f);
	expr_jit::free_expression(expr);
}

UTEST(generic_expr, expr2)
{
	expr_jit::expression_info info = {};
	info.expr = "(( (x + 1) * (y / 2) ) * (z + 1))";
	info.expr_len = uint32_t(strlen(info.expr));

	char const* arg_names[] = { "x", "y", "z" };
	info.variables = arg_names;
	info.num_variables = sizeof(arg_names) / sizeof(*arg_names);

	expr_jit::expr* expr = expr_jit::parse_expression(info, [](char const* _err) { printf(_err); });
	ASSERT_TRUE(expr);
	ASSERT_FALSE(expr_jit::is_expr_constant(expr));

	float args[] = { 5.0f, 2.0f, 3.0f };

	void* code = alloc_writeable_executable_page();
	expr_jit::jit_expr_x64(expr, (uint8_t*)code, 4096);
	float const val_jit = expr_jit::expr_jit_eval(code, args);

	float const val_real = (((args[0] + 1.0f) * (args[1] / 2.0f)) * (args[2] + 1.0f));

	ASSERT_TRUE(expr_jit::expr_eval(expr, args) == val_real);
	ASSERT_TRUE(expr_jit::expr_eval(expr, args) == val_jit);
	expr_jit::free_expression(expr);
}

UTEST_MAIN();