#include "expr_jit.h"

#include <string.h>
#include <stdio.h>

int main(int argc, char** argv)
{
	expr_jit::expression_info info = {};
	info.expr = "2 * (4 + -2*x)";
	info.expr_len = uint32_t(strlen(info.expr));
	
	char const* vars[] = { "x" };

	info.variables = vars;
	info.num_variables = sizeof(vars) / sizeof(*vars);

	expr_jit::expr* expr = expr_jit::parse_expression(info, [](char const* _err) { printf(_err); });

	float const args[] = { 5.0f };

	float const val = expr_jit::expr_eval(expr, args);
	printf("val: %.2f", val);
}