#include <assert.h>
#include <malloc.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>

#include "expr_jit.h"

namespace expr_jit
{

static void* malloc_wrapper(void*, size_t _size)
{
	return malloc(_size);
}

static void free_wrapper(void*, void* _ptr)
{
	free(_ptr);
}

static void null_err_cb(char const*)
{
}

static uint32_t next_pow2(uint32_t v)
{
	v--;
	v |= v >> 1;
	v |= v >> 2;
	v |= v >> 4;
	v |= v >> 8;
	v |= v >> 16;
	v++;
	return v;
}

static uint32_t fnv1a(char const* _str)
{
	uint32_t hash = 0x811c9dc5;
	while (*_str)
	{
		hash ^= *_str++;
		hash *= 16777619u;
	}
	return hash;
}

static uint32_t fnv1a(char const* _str, uint32_t _len)
{
	uint32_t hash = 0x811c9dc5;
	for(uint32_t i = 0; i < _len; ++i)
	{
		hash ^= _str[i];
		hash *= 16777619u;
	}
	return hash;
}

static void output_error(error_cb _err, char const* _fmt, ...)
{
	char buffer[256];
	va_list args;
	va_start(args, _fmt);
	vsnprintf(buffer, sizeof(buffer), _fmt, args);
	_err(buffer);
	va_end(args);
}


enum class symbol_type
{
	invalid,
	constant,
	variable
};

struct symbol
{
	char const* str;
	uint32_t str_len;
	symbol_type type;

	union
	{
		float constant_val;
		uint32_t variable_idx;
	};
};

struct symbol_table
{
	symbol* insert(char const* _str)
	{
		uint32_t const hash = fnv1a(_str);
		uint32_t idx = hash & count_mask;

		for (;;)
		{
			if (hashes[idx] == 0)
			{
				symbol* sym = &symbols[idx];
				sym->str = _str;
				sym->str_len = uint32_t(strlen(_str));
				return &symbols[idx];
			}

			if (hashes[idx] == hash && strcmp(symbols[idx].str, _str) == 0)
			{
				return &symbols[idx];
			}
			idx = (idx + 1) & count_mask;
		}
	}

	symbol* find(char const* _str, uint32_t _str_len)
	{
		uint32_t const hash = fnv1a(_str);
		uint32_t idx = hash & count_mask;

		for (;;)
		{
			if (hashes[idx] == 0)
			{
				return nullptr;
			}

			if (hashes[idx] == hash
				&& symbols[idx].str_len == _str_len
				&& strncmp(symbols[idx].str, _str, _str_len) == 0)
			{
				return &symbols[idx];
			}
		}
	}

	bool init(symbol* _symbol_mem, uint32_t* _hash_mem, uint32_t _max_entries, expression_info const* _expr_info, error_cb _err_cb)
	{
		symbols = _symbol_mem;
		hashes = _hash_mem;
		count_mask = _max_entries - 1;
		memset(_hash_mem, 0, sizeof(uint32_t) * _max_entries);
		memset(_symbol_mem, 0, sizeof(symbol) * _max_entries);

		for (uint32_t i = 0; i < _expr_info->num_variables; ++i)
		{
			char const* sym_string = _expr_info->variables[i];
			symbol* sym = insert(sym_string);
			if (sym->type != symbol_type::invalid)
			{
				output_error(_err_cb, "Variable symbol name \"%s\" is already defined.", sym_string);
				return false;
			}
			sym->type = symbol_type::variable;
			sym->variable_idx = i;
		}

		for (uint32_t i = 0; i < _expr_info->num_constants; ++i)
		{
			char const* sym_string = _expr_info->constant_names[i];
			symbol* sym = insert( sym_string);
			if (sym->type != symbol_type::invalid)
			{
				output_error(_err_cb, "Constant symbol name \"%s\" is already defined.", sym_string);
				return false;
			}

			sym->type = symbol_type::constant;
			sym->constant_val = _expr_info->constant_values[i];
		}

		return true;
	}


	symbol* symbols = nullptr;
	uint32_t* hashes = nullptr;

	// hash table size - 1
	uint32_t count_mask = 0;
};


struct expr
{
	alloc_hooks alloc;
};


struct parser_ctx
{
	void init(expr* _expr, expression_info const* _info, error_cb _err)
	{
		expression = _expr;
		expr_info = _info;
		err_cb = _err;
	}

	symbol_table symbols;

	expr* expression;
	expression_info const* expr_info;
	error_cb err_cb;
};

enum class token_type
{
	left_paren,
	right_paren,

	variable,
	constant,

	plus,
	minus,
	divide,
	multiply,

	symbol,

	eof
};

struct token
{
	token_type type;

	union
	{
		float constant_val;
		uint32_t variable_idx;
		symbol* symbol;
	};
};

struct lexer_ctx
{
	void init(symbol_table* _table, char const* _begin, char const* _end, error_cb _err)
	{
		begin = cur = _begin;
		eof = _end;
		error_cb = _err;
		sym_table = _table;
	}

	char const* begin;
	char const* cur;
	char const* eof;

	error_cb error_cb;
	symbol_table* sym_table;

	token peek;
};

static char to_lower(char c)
{
	return c >= 'A' && c <= 'Z' ? c + 'a' - 'A' : c;
}

bool lex_next(lexer_ctx& _ctx)
{
	do 
	{
		if (_ctx.cur == _ctx.eof)
		{
			_ctx.peek.type = token_type::eof;
			return true;
		}

		char const c = *_ctx.cur;

		switch (c)
		{
			case '(': _ctx.peek.type = token_type::left_paren; ++_ctx.cur; return true;
			case ')': _ctx.peek.type = token_type::right_paren; ++_ctx.cur; return true;
			case '+': _ctx.peek.type = token_type::plus; ++_ctx.cur; return true;
			case '*': _ctx.peek.type = token_type::multiply; ++_ctx.cur; return true;
			case '-': _ctx.peek.type = token_type::minus; ++_ctx.cur; return true;

			case '0':
			case '1':
			case '2':
			case '3':
			case '4':
			case '5':
			case '6':
			case '7':
			case '8':
			case '9':
			{
				_ctx.peek.type = token_type::constant;
				_ctx.peek.constant_val = strtof(_ctx.cur, (char**)&_ctx.cur);
				return true;
			} break;

			case ' ':
			case '\n':
			case '\t':
			case '\r':
			{
				++_ctx.cur;
			} break;

			default:
			{
				char const c_lower = to_lower(c);
				if (c_lower >= 'a' && c_lower <= 'z')
				{
					char const* str_begin = _ctx.cur++;
					char next_c = to_lower(*_ctx.cur);
					while (next_c >= 'a' && next_c <= 'z')
					{
						next_c = *_ctx.cur++;
					}

					symbol* sym = _ctx.sym_table->find(str_begin, uint32_t(_ctx.cur - str_begin));
					
					if (!sym)
					{
						output_error(_ctx.error_cb, "Found undeclared symbol: \"%.*s\".", uint32_t(_ctx.cur - str_begin), str_begin);
						return false;
					}

					_ctx.peek.type = token_type::symbol;
					_ctx.peek.symbol = sym;
					return true;
				}

				output_error(_ctx.error_cb, "Unexpected token '%c' at index %u", *_ctx.cur, uint32_t(_ctx.cur - _ctx.begin));
				return false;
			} break;
		}
	} while (true);
}


static bool parse_expr_internal(parser_ctx& _parser, lexer_ctx& _lexer)
{
	return false;
}

expr* parse_expression(expression_info const& _info, error_cb _error_cb /*= nullptr*/, alloc_hooks* _alloc_hooks /*= nullptr*/)
{
	alloc_hooks hooks;
	if (_alloc_hooks)
	{
		hooks = *_alloc_hooks;
	}
	else
	{
		hooks.ctx = nullptr;
		hooks.alloc = malloc_wrapper;
		hooks.free = free_wrapper;
	}

	error_cb err_cb = _error_cb ? _error_cb : null_err_cb;

	expr* expression = (expr*)hooks.alloc(hooks.ctx, sizeof(expr));
	expression->alloc = hooks;

	parser_ctx parser;
	parser.init(expression, &_info, err_cb);

	uint32_t const sym_entries = next_pow2(_info.num_constants + _info.num_variables + 1);

	uint32_t* sym_hashes = (uint32_t*)alloca(sizeof(uint32_t) * sym_entries);
	symbol* symbols = (symbol*)alloca(sizeof(symbol) * sym_entries);
	symbol_table sym_table;
	sym_table.init(symbols, sym_hashes, sym_entries, &_info, err_cb);

	lexer_ctx lexer;
	lexer.init(&sym_table, _info.expr, _info.expr + _info.expr_len, err_cb);

	// Init peek.
	lex_next(lexer);

	if (!parse_expr_internal(parser, lexer))
	{
		// TODO: Free expr.
		return nullptr;
	}

	return expression;
}

void free_expression(expr* _expr)
{
	if (!_expr)
	{
		return;
	}

	// TODO: Free any internal structures.
	_expr->alloc.free(_expr->alloc.ctx, _expr);
}

} // namespace expr_jit