#include <malloc.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <math.h>

#include "expr_jit.h"

#if EXPR_JIT_COMPILER_MSVC
extern "C" unsigned char _BitScanForward(unsigned long * _Index, unsigned long _Mask);
#pragma intrinsic(_BitScanForward)

extern "C" unsigned char _BitScanReverse(unsigned long * _Index, unsigned long _Mask);
#pragma intrinsic(_BitScanReverse)
#endif

namespace expr_jit
{

uint32_t constexpr c_sign_bit = 0x80000000;
uint32_t constexpr c_sign_mask = 0x7fffffff;


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

static uint32_t find_first_set_lsb(uint32_t _v)
{
#if EXPR_JIT_COMPILER_CLANG || EXPR_JIT_COMPILER_GCC
	return __builtin_ctz(_v);
#elif EXPR_JIT_COMPILER_MSVC
	unsigned long idx;
	return ::_BitScanForward(&idx, _v) ? idx : 32;
#else
#error Not implemented
#endif
}

static uint32_t find_first_set_msb(uint32_t _v)
{
#if EXPR_JIT_COMPILER_CLANG || EXPR_JIT_COMPILER_GCC
	return __builtin_clz(_v);
#elif EXPR_JIT_COMPILER_MSVC
	unsigned long idx;
	return ::_BitScanReverse(&idx, _v) ? idx : 32;
#else
#error Not implemented
#endif
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

template <typename T>
void swap(T& _lhs, T& _rhs)
{
	T temp = _lhs;
	_lhs = _rhs;
	_rhs = temp;
}

template <typename T>
struct dyn_pod_array
{
	dyn_pod_array() = default;

	~dyn_pod_array()
	{
		if (mem)
		{
			hooks.free(hooks.ctx, mem);
		}
	}

	dyn_pod_array(dyn_pod_array const&) = delete;
	dyn_pod_array& operator=(dyn_pod_array const&) = delete;

	void init(alloc_hooks _hooks)
	{
		hooks = _hooks;
	}

	void ensure_cap(uint32_t _req_cap)
	{
		if (cap < _req_cap)
		{
			uint32_t const amortized_grow = cap + cap / 2;
			uint32_t const new_cap = amortized_grow < _req_cap ? _req_cap : amortized_grow;
			
			T* new_mem = (T*)hooks.alloc(hooks.ctx, sizeof(T) * new_cap);
			
			if (mem)
			{
				memcpy(new_mem, mem, size * sizeof(T));
				hooks.free(hooks.ctx, mem);
			}
			cap = new_cap;
			mem = new_mem;
		}
	}

	void append(T const& _v)
	{
		*append() = _v;
	}

	T* append()
	{
		ensure_cap(size + 1);
		return &mem[size++];
	}

	T* append_n(uint32_t _n)
	{
		ensure_cap(size + _n);
		T* ptr = mem + size;
		size += _n;
		return ptr;
	}

	T* begin()
	{
		return mem;
	}

	T* end()
	{
		return mem + size;
	}

	T& operator[](uint32_t _idx)
	{
		EXPR_JIT_ASSERT(_idx < size);
		return mem[_idx];
	}

	T* mem = nullptr;
	uint32_t size = 0;
	uint32_t cap = 0;

	alloc_hooks hooks;
};

enum class builtin_function
{
	abs,
	min,
	max,
	sqrt,
	clamp,

	num_functions
};

char const* c_builtin_function_name[uint32_t(builtin_function::num_functions)]
{
	"abs",
	"min",
	"max",
	"sqrt",
	"clamp"
};

static uint32_t const c_builtin_function_num_param[uint32_t(builtin_function::num_functions)] =
{
	1,
	2,
	2,
	1,
	3
};


enum class symbol_type
{
	invalid,
	constant,
	variable,
	function
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
		builtin_function function;
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
				hashes[idx] = hash;
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
		uint32_t const hash = fnv1a(_str, _str_len);
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

			idx = (idx + 1) & count_mask;
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

		for (uint32_t i = 0; i < uint32_t(builtin_function::num_functions); ++i)
		{
			char const* sym_string = c_builtin_function_name[i];
			symbol* sym = insert(sym_string);
			if (sym->type != symbol_type::invalid)
			{
				output_error(_err_cb, "Function symbol name \"%s\" is already defined.", sym_string);
				return false;
			}

			sym->type = symbol_type::function;
			sym->function = builtin_function(i);
		}

		return true;
	}


	symbol* symbols = nullptr;
	uint32_t* hashes = nullptr;

	// hash table size - 1
	uint32_t count_mask = 0;
};




enum class ast_node_type
{
	constant,
	variable,
	function,

	bin_add,
	bin_sub,
	bin_mul,
	bin_div,

	un_neg
};

struct ast_node
{
	bool is_constant() const { return type == ast_node_type::constant; }
	bool is_constant_or_var() const { return type == ast_node_type::constant || type == ast_node_type::variable; }

	uint32_t get_fun_param_count() const { EXPR_JIT_ASSERT(type == ast_node_type::function); return c_builtin_function_num_param[uint32_t(function.index)]; }

	ast_node_type type;
	uint32_t node_id;

	union
	{
		float constant_val;
		uint32_t variable_idx;

		struct
		{
			ast_node* left;
			ast_node* right;
		} binary_op;

		struct  
		{
			builtin_function index;
			ast_node* params[3];
		} function;

		ast_node* unary_op_child;

		ast_node* free_list_next;
	};
};

template <typename VisitFn>
static void visit_ast_depth_first_post_order(ast_node* _node, VisitFn const& _fn)
{
	switch (_node->type)
	{
		case ast_node_type::bin_add:
		case ast_node_type::bin_sub:
		case ast_node_type::bin_mul:
		case ast_node_type::bin_div:
		{
			ast_node* left_node = _node->binary_op.left;
			ast_node* right_node = _node->binary_op.right;

			visit_ast_depth_first_post_order(left_node, _fn);
			visit_ast_depth_first_post_order(right_node, _fn);
		} break;

		case ast_node_type::un_neg:
		{
			visit_ast_depth_first_post_order(_node->unary_op_child, _fn);
		} break;

		case ast_node_type::function:
		{
			for (ast_node* param : _node->function.params)
			{
				if (param)
				{
					visit_ast_depth_first_post_order(param, _fn);
				}
			}
		} break;

		default:
		{
		} break;
	}

	_fn(_node);
}

struct ast_node_pool
{
	static uint32_t const c_nodes_per_chunk = 32;
	
	struct chunk
	{
		chunk* next_chunk;
		ast_node nodes[c_nodes_per_chunk];
		uint32_t next_node;
	};


	void free_all(alloc_hooks _hooks)
	{
		chunk* c = chunk_list;
		while (c)
		{
			chunk* next = c->next_chunk;
			_hooks.free(_hooks.ctx, c);
			c = next;
		}
	}

	ast_node* alloc_node(alloc_hooks const& _hooks)
	{
		if (!free_list || !chunk_list || chunk_list->next_node == c_nodes_per_chunk)
		{
			chunk* c = (chunk*)_hooks.alloc(_hooks.ctx, sizeof(chunk));
			memset(c->nodes, 0, sizeof(c->nodes));

			c->next_chunk = chunk_list;
			chunk_list = c;
			c->next_node = 0;
		}

		if (free_list)
		{
			ast_node* n = free_list;
			free_list = n->free_list_next;
			return n;
		}
		else
		{
			ast_node* n = &chunk_list->nodes[chunk_list->next_node++];
			n->node_id = total_nodes++;
			return n;
		}
	}

	// Note: not necessary for leaks (whole pool is freed), only used to recycle nodes when performing transformations on AST.
	void free_node(ast_node* _n)
	{
		visit_ast_depth_first_post_order(_n, [this](ast_node* _node) 
		{
			_node->free_list_next = free_list;
			free_list = _node;
		});
	}

	chunk* chunk_list;
	ast_node* free_list;

	uint32_t total_nodes;
};

struct expr
{
	ast_node* alloc_ast_node()
	{
		return node_pool.alloc_node(alloc);
	}

	alloc_hooks alloc;
	ast_node_pool node_pool;
	uint32_t num_variables;

	ast_node* root = nullptr;
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
	comma,

	constant,

	symbol,

	plus,
	minus,
	divide,
	multiply,

	eof
};

struct token
{
	token_type type;

	union
	{
		float constant_val;
		symbol* sym;
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

static bool lex_next(lexer_ctx& _ctx)
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
			case '/': _ctx.peek.type = token_type::divide; ++_ctx.cur; return true;
			case ',': _ctx.peek.type = token_type::comma; ++_ctx.cur; return true;

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
						next_c = *(++_ctx.cur);
					}

					symbol* sym = _ctx.sym_table->find(str_begin, uint32_t(_ctx.cur - str_begin));
					
					if (!sym)
					{
						output_error(_ctx.error_cb, "Found undeclared symbol: \"%.*s\".", uint32_t(_ctx.cur - str_begin), str_begin);
						return false;
					}

					_ctx.peek.type = token_type::symbol;
					_ctx.peek.sym = sym;

					return true;
				}

				output_error(_ctx.error_cb, "Unexpected token '%c' at index %u", *_ctx.cur, uint32_t(_ctx.cur - _ctx.begin));
				return false;
			} break;
		}
	} while (true);
}

static bool lex_expect(lexer_ctx& _lexer, token_type _type)
{
	if (_lexer.peek.type != _type)
	{
		return false;
	}

	lex_next(_lexer);
	return true;
}

static ast_node* parse_expr_ast(parser_ctx& _parser, lexer_ctx& _lexer);
static ast_node* parse_term_ast(parser_ctx& _parser, lexer_ctx& _lexer);
static ast_node* parse_factor_ast(parser_ctx& _parser, lexer_ctx& _lexer);
static float eval_node(ast_node const* _node, float const* _args);

static ast_node* parse_factor_ast(parser_ctx& _parser, lexer_ctx& _lexer)
{
	// factor -> [-] constant | variable | function | (expr)
	ast_node* neg_node = nullptr;
	ast_node* factor_node = nullptr;

	if (_lexer.peek.type == token_type::minus)
	{
		lex_next(_lexer);
		neg_node = _parser.expression->alloc_ast_node();
		neg_node->type = ast_node_type::un_neg;
	}

	switch (_lexer.peek.type)
	{
		case token_type::symbol:
		{
			token const tok = _lexer.peek;
			lex_next(_lexer);

			switch (tok.sym->type)
			{
				case symbol_type::constant:
				{
					factor_node = _parser.expression->alloc_ast_node();
					factor_node->type = ast_node_type::constant;
					factor_node->constant_val = tok.sym->constant_val;
				} break;

				case symbol_type::variable:
				{
					factor_node = _parser.expression->alloc_ast_node();
					factor_node->type = ast_node_type::variable;
					factor_node->variable_idx = tok.sym->variable_idx;
				} break;

				case symbol_type::function:
				{
					factor_node = _parser.expression->alloc_ast_node();
					factor_node->type = ast_node_type::function;
					factor_node->function.index = tok.sym->function;
					uint32_t const fn_params = c_builtin_function_num_param[uint32_t(tok.sym->function)];
					
					if (!lex_expect(_lexer, token_type::left_paren))
					{
						output_error(_lexer.error_cb, "Expected '(' after function \"%s\"", c_builtin_function_name[uint32_t(tok.sym->function)]);
						return nullptr;
					}

					for (uint32_t i = 0; i < fn_params; ++i)
					{
						factor_node->function.params[i] = parse_expr_ast(_parser, _lexer);
						if (!factor_node->function.params[i])
						{
							return nullptr;
						}

						if (i != fn_params - 1)
						{
							if (!lex_expect(_lexer, token_type::comma))
							{
								output_error(_lexer.error_cb, "Expected ',' after param %u for function \"%s\"", i, c_builtin_function_name[uint32_t(tok.sym->function)]);
								return nullptr;
							}
						}
					}

					if (!lex_expect(_lexer, token_type::right_paren))
					{
						output_error(_lexer.error_cb, "Expected ')' after function \"%s\"", c_builtin_function_name[uint32_t(tok.sym->function)]);
						return nullptr;
					}

				} break;
			}

		} break;

		case token_type::constant:
		{
			lex_next(_lexer);
			factor_node = _parser.expression->alloc_ast_node();
			factor_node->type = ast_node_type::constant;
			factor_node->constant_val = _lexer.peek.constant_val;
		} break;

		case token_type::left_paren:
		{
			lex_next(_lexer);
			factor_node = parse_expr_ast(_parser, _lexer);
			if (!factor_node || !lex_expect(_lexer, token_type::right_paren))
			{
				return nullptr;
			}
		} break;
	}

	if (factor_node && neg_node)
	{
		neg_node->unary_op_child = factor_node;
		return neg_node;
	}

	return factor_node;
}

static ast_node* parse_term_ast(parser_ctx& _parser, lexer_ctx& _lexer)
{
	// term -> term * factor | term / factor | factor

	ast_node* node = parse_factor_ast(_parser, _lexer);
	if (!node)
	{
		return nullptr;
	}

	while (_lexer.peek.type == token_type::divide
		   || _lexer.peek.type == token_type::multiply)
	{
		token const tok = _lexer.peek;
		lex_next(_lexer);
		ast_node* bin_op = _parser.expression->alloc_ast_node();
		bin_op->type = tok.type == token_type::divide ? ast_node_type::bin_div : ast_node_type::bin_mul;
		bin_op->binary_op.left = node;
		bin_op->binary_op.right = parse_factor_ast(_parser, _lexer);
		
		if (!bin_op->binary_op.right)
		{
			return nullptr;
		}
		node = bin_op;
	}
	return node;
}

static ast_node* parse_expr_ast(parser_ctx& _parser, lexer_ctx& _lexer)
{
	// expr -> expr + term | expr - term | term

	ast_node* node = parse_term_ast(_parser, _lexer);
	
	while (_lexer.peek.type == token_type::plus
		   || _lexer.peek.type == token_type::minus)
	{
		token const tok = _lexer.peek;
		lex_next(_lexer);
		ast_node* bin_op = _parser.expression->alloc_ast_node();
		bin_op->type = tok.type == token_type::plus ? ast_node_type::bin_add : ast_node_type::bin_sub;
		bin_op->binary_op.left = node;
		bin_op->binary_op.right = parse_term_ast(_parser, _lexer);
		if (!bin_op->binary_op.right)
		{
			return nullptr;
		}
		node = bin_op;
	}

	return node;
}



static void optimize_fold_constants(ast_node* _root, expr* _expr)
{
	visit_ast_depth_first_post_order(_root, [_expr](ast_node* _node)
	{
		switch (_node->type)
		{
			case ast_node_type::bin_add:
			case ast_node_type::bin_sub:
			case ast_node_type::bin_mul:
			case ast_node_type::bin_div:
			{
				if (_node->binary_op.left->type == ast_node_type::constant
					&& _node->binary_op.right->type == ast_node_type::constant)
				{
					float const val = eval_node(_node, nullptr);
					_expr->node_pool.free_node(_node->binary_op.left);
					_expr->node_pool.free_node(_node->binary_op.right);
					
					_node->constant_val = val;
					_node->type = ast_node_type::constant;
				}

			} break;

			case ast_node_type::un_neg:
			{
				if (_node->unary_op_child->type == ast_node_type::constant)
				{
					float const val = -_node->unary_op_child->constant_val;
					_expr->node_pool.free_node(_node->unary_op_child);

					_node->type = ast_node_type::constant;
					_node->constant_val = val;
				}
			} break;

			case ast_node_type::function:
			{
				uint32_t const param_count = _node->get_fun_param_count();
				bool can_fold = true;
				for (uint32_t i = 0; i < param_count; ++i)
				{
					can_fold &= _node->function.params[i]->is_constant();
				}

				if (can_fold)
				{
					float const eval = eval_node(_node, nullptr);

					for (uint32_t i = 0; i < param_count; ++i)
					{
						_expr->node_pool.free_node(_node->function.params[i]);
					}

					_node->type = ast_node_type::constant;
					_node->constant_val = eval;
				}

			} break;

			default:
			{
			} break;
		}
	});
}

static void optimize_strength_reduction(ast_node* _root)
{
	visit_ast_depth_first_post_order(_root, [](ast_node* _node)
	{
		switch (_node->type)
		{
			case ast_node_type::bin_div:
			{
				// Replace division of constant with multiplication by reciprocal.
				if (_node->binary_op.right->type == ast_node_type::constant)
				{
					_node->binary_op.right->constant_val = 1.0f / _node->binary_op.right->constant_val;
					_node->type = ast_node_type::bin_mul;
				}

			} break;

			default:
			{
			} break;
		}
	});

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
	memset(expression, 0, sizeof(expr));
	expression->alloc = hooks;
	expression->num_variables = _info.num_variables;

	parser_ctx parser;
	parser.init(expression, &_info, err_cb);

	uint32_t const sym_entries = next_pow2(_info.num_constants + _info.num_variables + uint32_t(builtin_function::num_functions) + 1);

	uint32_t* sym_hashes = (uint32_t*)alloca(sizeof(uint32_t) * sym_entries);
	symbol* symbols = (symbol*)alloca(sizeof(symbol) * sym_entries);
	symbol_table sym_table;
	sym_table.init(symbols, sym_hashes, sym_entries, &_info, err_cb);

	lexer_ctx lexer;
	lexer.init(&sym_table, _info.expr, _info.expr + _info.expr_len, err_cb);

	// Init peek.
	lex_next(lexer);

	expression->root = parse_expr_ast(parser, lexer);
	if (!expression->root)
	{
		free_expression(expression);
		return nullptr;
	}
	
	optimize_fold_constants(expression->root, expression);
	optimize_strength_reduction(expression->root);

	return expression;
}

void free_expression(expr* _expr)
{
	if (!_expr)
	{
		return;
	}

	_expr->node_pool.free_all(_expr->alloc);
	_expr->alloc.free(_expr->alloc.ctx, _expr);
}

static float eval_node(ast_node const* _node, float const* _args)
{
	switch (_node->type)
	{
		case ast_node_type::bin_add:
		{
			return eval_node(_node->binary_op.left, _args) + eval_node(_node->binary_op.right, _args);
		} break;

		case ast_node_type::bin_sub:
		{
			return eval_node(_node->binary_op.left, _args) - eval_node(_node->binary_op.right, _args);
		} break;

		case ast_node_type::bin_mul:
		{
			return eval_node(_node->binary_op.left, _args) * eval_node(_node->binary_op.right, _args);
		} break;

		case ast_node_type::bin_div:
		{
			return eval_node(_node->binary_op.left, _args) / eval_node(_node->binary_op.right, _args);
		} break;

		case ast_node_type::un_neg:
		{
			return -eval_node(_node->unary_op_child, _args);
		} break;
	
		case ast_node_type::variable:
		{
			return _args[_node->variable_idx];
		} break;

		case ast_node_type::constant:
		{
			return _node->constant_val;
		} break;

		case ast_node_type::function:
		{
			switch (_node->function.index)
			{
				case builtin_function::abs: return fabsf(eval_node(_node->function.params[0], _args));
				case builtin_function::min:
				{
					float const f0 = eval_node(_node->function.params[0], _args);
					float const f1 = eval_node(_node->function.params[1], _args);
					return f0 < f1 ? f0 : f1;
				} break;

				case builtin_function::max:
				{
					float const f0 = eval_node(_node->function.params[0], _args);
					float const f1 = eval_node(_node->function.params[1], _args);
					return f0 > f1 ? f0 : f1;
				} break;

				case builtin_function::sqrt: return sqrtf(eval_node(_node->function.params[0], _args));

				case builtin_function::clamp:
				{
					float const x = eval_node(_node->function.params[0], _args);
					float const min = eval_node(_node->function.params[1], _args);
					float const max = eval_node(_node->function.params[2], _args);
					float const a = (x > max ? max : x);
					return a < min ? min : a;
				} break;
			}
		} break;

		default:
		{
			EXPR_JIT_ASSERT(false);
		} break;
	}

	
	EXPR_JIT_UNREACHABLE;
}

bool is_expr_constant(expr const* _expr)
{
	EXPR_JIT_ASSERT(_expr && _expr->root);
	return _expr->root->type == ast_node_type::constant;
}

float expr_eval(expr const* _expr, float const* _args)
{
	EXPR_JIT_ASSERT(_expr && _expr->root);
	return eval_node(_expr->root, _args);
}

// X64 Codegen.


enum xmm_reg
{
	xmm0,
	xmm1,
	xmm2,
	xmm3,
	xmm4,
	xmm5,
	xmm6,
	xmm7,
	xmm8,
	xmm9,
	xmm10,
	xmm11,
	xmm12,
	xmm13,
	xmm14,
	xmm15,

	num_reg
};

struct operand_location
{
	enum class operand_type
	{
		invalid,
		xmm,
		constant,
		arg_offset
	};

	void set_as_xmm(xmm_reg _reg)
	{
		reg = _reg;
		type = operand_type::xmm;
	}

	void set_as_arg(uint32_t _arg_idx)
	{
		arg_index = _arg_idx;
		type = operand_type::arg_offset;
	}

	void set_as_constant(uint32_t _constant_idx)
	{
		type = operand_type::constant;
		constant_idx = _constant_idx;
	}

	bool is_register() const
	{
		return type == operand_type::xmm;
	}

	operand_type type = operand_type::invalid;

	xmm_reg reg;

	union
	{
		uint32_t constant_idx;
		uint32_t arg_index;
	};
};

struct register_allocator
{
	operand_location alloc_reg()
	{
		// TODO: Spill
		EXPR_JIT_ASSERT(free_reg_mask);
		operand_location loc;
		loc.set_as_xmm(xmm_reg(find_first_set_lsb(free_reg_mask)));
		set_reg_used(loc.reg);
		return loc;
	}

	void set_reg_used(xmm_reg _reg)
	{
		EXPR_JIT_ASSERT((1 << _reg) & free_reg_mask);
		free_reg_mask &= ~(1 << _reg);
	}

	void set_reg_unused(xmm_reg _reg)
	{
		EXPR_JIT_ASSERT(!((1 << _reg) & free_reg_mask));
		free_reg_mask |= 1 << _reg;
	}

	uint32_t free_reg_mask = (1 << xmm_reg::num_reg) - 1;
};

struct constant_relocation
{
	uint8_t* rip;
	uint8_t* constant_write_loc;
	uint32_t constant_idx;
};

struct constant_info
{
	uint32_t value;
	uint32_t uses;
	xmm_reg cur_reg;
	bool is_16b;
};

struct variable_info
{
	uint32_t uses;
	xmm_reg cur_reg;
};

struct x64_writer_ctx
{
	uint32_t get_constant_index(float _constant)
	{
		uint32_t constu32;
		memcpy(&constu32, &_constant, sizeof(uint32_t));
		return get_constant_index(constu32);
	}

	uint32_t get_constant_index_128(uint32_t _constant)
	{
		for (uint32_t i = 0; i < constants.size / 4; ++i)
		{
			bool equal = true;
			equal &= constants[i + 0].value	== _constant;
			equal &= constants[i + 1].value == _constant;
			equal &= constants[i + 2].value	== _constant;
			equal &= constants[i + 3].value == _constant;

			if (equal)
			{
				return i * 4;
			}
		}

		// Align to 16 bytes.
		if (uint32_t const align_offs = ((constants.size + 15) & ~15) - constants.size)
		{
			constants.append_n(align_offs);
		}

		uint32_t const idx = constants.size;
		constant_info* info = constants.append_n(4);
		info[0].value = info[1].value = info[2].value = info[3].value = _constant;
		info->cur_reg = xmm_reg::num_reg;
		info->uses = 0;
		info->is_16b = true;

		return idx;
	}

	uint32_t get_constant_index(uint32_t _constant)
	{
		for (uint32_t i = 0; i < constants.size; ++i)
		{
			if (constants[i].value == _constant)
			{
				return i;
			}
		}	

		uint32_t const idx = constants.size;
		constant_info* info = constants.append();
		info->cur_reg = xmm_reg::num_reg;
		info->uses = 0;
		info->value = _constant;
		info->is_16b = false;

		return idx;
	}

	void init(expr const* _expr, uint8_t* _buff, size_t _buff_size)
	{
		expr = _expr;
		buff_begin = _buff;
		buff_cur = _buff;
		buff_end = _buff + _buff_size;
		bytes_written = 0;

		constants.init(_expr->alloc);
		rip_disp32_relocs.init(_expr->alloc);
		variables.init(_expr->alloc);
		variables.append_n(_expr->num_variables);

		for (variable_info& var_info : variables)
		{
			var_info.cur_reg = xmm_reg::num_reg;
			var_info.uses = 0;
		}
	}

	void write_u32(uint32_t _v)
	{
		if (buff_end - buff_cur >= sizeof(uint32_t))
		{
			memcpy(buff_cur, &_v, sizeof(uint32_t));
		}

		buff_cur += sizeof(uint32_t);
		bytes_written += sizeof(uint32_t);
	}

	void write_u8(uint8_t _v)
	{
		if (buff_end != buff_cur)
		{
			*buff_cur++ = _v;
		}

		++bytes_written;
	}

	void write_constants_and_relocate()
	{
		// align to 16 bytes
		uintptr_t bytes_to_16b_align = ((uintptr_t(buff_cur) + 15) & ~15) - uintptr_t(buff_cur);
		while (bytes_to_16b_align--)
		{
			write_u8(0);
		}

		uint8_t* reloc_base = buff_cur;

		for (constant_info const& info : constants)
		{
			write_u32(info.value);
		}

		for (constant_relocation& reloc : rip_disp32_relocs)
		{
			uint8_t* const abs_address = reloc_base + reloc.constant_idx * sizeof(float);
			EXPR_JIT_ASSERT(abs_address > reloc.rip);
			uintptr_t const offset = abs_address - reloc.rip;
			EXPR_JIT_ASSERT(offset <= INT32_MAX);

			if (buff_end - reloc.constant_write_loc >= 4)
			{
				int32_t const offs32 = int32_t(offset);
				memcpy(reloc.constant_write_loc, &offs32, sizeof(int32_t));
			}
		}
	}

	expr const* expr;

	register_allocator reg_alloc;

	dyn_pod_array<constant_info> constants;
	dyn_pod_array<variable_info> variables;
	dyn_pod_array<constant_relocation> rip_disp32_relocs;

	uint8_t* buff_begin;
	uint8_t* buff_cur;
	uint8_t* buff_end;

	uint32_t bytes_written;

	void* write_ctx;
};

namespace x64_prefix
{

enum : uint8_t
{
	sse_f32 = 0xF3,
	two_byte_opcode = 0x0F
};

} // namespace x64_prefix

static bool operand_requires_rex_prefix(operand_location const& _operand)
{
	return _operand.is_register() && _operand.reg > xmm7;
}

static void x64_sse_binary_op(x64_writer_ctx& _writer, operand_location const& _op0, operand_location const& _op1, uint8_t _instruction_prefix, bool _sse_ps = false)
{
	EXPR_JIT_ASSERT(_op1.is_register());

	if (!_sse_ps)
	{
		// sse prefix first
		_writer.write_u8(x64_prefix::sse_f32);
	}

	uint8_t rex_byte = 0;

	if (operand_requires_rex_prefix(_op0))
	{
		// REX.B
		rex_byte |= 0b0001;
	}

	if (operand_requires_rex_prefix(_op1))
	{
		// REX.R
		rex_byte |= 0b0100;
	}

	// Rex prefix if necessary.
	if (rex_byte)
	{
		_writer.write_u8(0x40 | rex_byte);
	}

	// Two byte opcode prefix.
	_writer.write_u8(x64_prefix::two_byte_opcode);

	_writer.write_u8(_instruction_prefix);

	// ModR/M byte.
	{
		uint8_t rm;
		uint32_t displacement = 0;
		uint8_t mod;
		
		bool displace_is_32_bit;

		constant_relocation* reloc = nullptr;
		
		switch (_op0.type)
		{
			case operand_location::operand_type::xmm:
			{
				mod = 0x3;
				rm = uint8_t(_op0.reg > xmm7 ? _op0.reg - 8 : _op0.reg);
			} break;

			case operand_location::operand_type::arg_offset:
			{
				// win64 - args in RCX. 
				// TODO: other calling conventions.
				rm = 0x1;

				if (_op0.arg_index == 0)
				{
					// [RCX]
					mod = 0x0;
				}
				else
				{
					// [RCX + disp]
					displacement = _op0.arg_index * sizeof(float);
					mod = displacement > 255 ? 0x2 : 0x1;
					displace_is_32_bit = displacement > 255;
				}
			} break;

			case operand_location::operand_type::constant:
			{
				// [RIP + disp32]
				mod = 0x0;
				rm = 0x5;
				displacement = UINT32_MAX;
				displace_is_32_bit = true;
				reloc = _writer.rip_disp32_relocs.append();
				reloc->constant_idx = _op0.constant_idx;
			} break;
		}

		uint8_t const reg = uint8_t(_op1.reg > xmm7 ? _op1.reg - 8 : _op1.reg);
		_writer.write_u8(rm | (reg << 3) | (mod << 6));

		if (displacement)
		{
			if (reloc)
			{
				reloc->constant_write_loc = _writer.buff_cur;
			}

			if (displace_is_32_bit)
			{
				_writer.write_u32(displacement);
			}
			else
			{
				_writer.write_u8(displacement);
			}

			if (reloc)
			{
				reloc->rip = _writer.buff_cur;
			}
		}
	}
}

static void x64_movss(x64_writer_ctx& _writer, operand_location const& _dest, operand_location const& _src)
{
	if (!_dest.is_register())
	{
		EXPR_JIT_ASSERT(_src.is_register());
		x64_sse_binary_op(_writer, _dest, _src, 0x11);
	}
	else
	{
		x64_sse_binary_op(_writer, _src, _dest, 0x10);
	}
}

static void x64_mulss(x64_writer_ctx& _writer, operand_location const& _dest, operand_location const& _src)
{
	EXPR_JIT_ASSERT(_dest.is_register());
	x64_sse_binary_op(_writer, _src, _dest, 0x59);
}

static void x64_divss(x64_writer_ctx& _writer, operand_location const& _dest, operand_location const& _src)
{
	EXPR_JIT_ASSERT(_dest.is_register());
	x64_sse_binary_op(_writer, _src, _dest, 0x5e);
}

static void x64_addss(x64_writer_ctx& _writer, operand_location const& _dest, operand_location const& _src)
{
	EXPR_JIT_ASSERT(_dest.is_register());
	x64_sse_binary_op(_writer, _src, _dest, 0x58);
}

static void x64_subss(x64_writer_ctx& _writer, operand_location const& _dest, operand_location const& _src)
{
	EXPR_JIT_ASSERT(_dest.is_register());
	x64_sse_binary_op(_writer, _src, _dest, 0x5c);
}

static void x64_minss(x64_writer_ctx& _writer, operand_location const& _dest, operand_location const& _src)
{
	EXPR_JIT_ASSERT(_dest.is_register());
	x64_sse_binary_op(_writer, _src, _dest, 0x5d);
}

static void x64_maxss(x64_writer_ctx& _writer, operand_location const& _dest, operand_location const& _src)
{
	EXPR_JIT_ASSERT(_dest.is_register());
	x64_sse_binary_op(_writer, _src, _dest, 0x5f);
}

static void x64_sqrtss(x64_writer_ctx& _writer, operand_location const& _dest, operand_location const& _src)
{
	EXPR_JIT_ASSERT(_dest.is_register());
	x64_sse_binary_op(_writer, _src, _dest, 0x51);
}

static void x64_and_ps(x64_writer_ctx& _writer, operand_location const& _dest, operand_location const& _src)
{
	EXPR_JIT_ASSERT(_dest.is_register());
	x64_sse_binary_op(_writer, _src, _dest, 0x54, true);
}

static void x64_xorps(x64_writer_ctx& _writer, operand_location const& _dest, operand_location const& _src)
{
	EXPR_JIT_ASSERT(_dest.is_register());
	x64_sse_binary_op(_writer, _src, _dest, 0x57, true);
}

static void x64_ret(x64_writer_ctx& _writer)
{
	_writer.write_u8(0xc3);
}

static operand_location load_constant_or_var(x64_writer_ctx& _writer, ast_node* _node, xmm_reg* o_reg_to_free)
{
	// TODO: we should cache constant index from pre-pass.
	xmm_reg* reg = nullptr;
	uint32_t* uses = nullptr;

	operand_location ret_loc;

	*o_reg_to_free = xmm_reg::num_reg;

	EXPR_JIT_ASSERT(_node->is_constant_or_var());

	uint32_t constant_idx = 0;

	if (_node->is_constant())
	{
		float const constant_val = _node->constant_val;
		constant_idx = _writer.get_constant_index(constant_val);
		constant_info& const_info = _writer.constants[constant_idx];
		EXPR_JIT_ASSERT(const_info.uses > 0);
		reg = &const_info.cur_reg;
		uses = &const_info.uses;
	}
	else
	{
		EXPR_JIT_ASSERT(_node->type == ast_node_type::variable);
		variable_info& var_info = _writer.variables[_node->variable_idx];
		reg = &var_info.cur_reg;
		uses = &var_info.uses;
	}


	if (*reg != xmm_reg::num_reg)
	{
		// constant already in a register - make use of it.
		ret_loc.set_as_xmm(*reg);
		if (*uses == 0)
		{
			*o_reg_to_free = *reg;
			*reg = xmm_reg::num_reg;
		}
	}
	else
	{
		if (--(*uses) > 0)
		{
			// There is another use of this constant/var, so lets try and load it into a register.
			// TODO: Broken with spill.
			ret_loc = _writer.reg_alloc.alloc_reg();
			*reg = ret_loc.reg;
			operand_location src_loc;

			if (_node->is_constant())
			{
				src_loc.set_as_constant(constant_idx);
			}
			else
			{
				src_loc.set_as_arg(_node->variable_idx);
			}

			x64_movss(_writer, ret_loc, src_loc);
		}
		else
		{
			// address it directly.
			if (_node->is_constant())
			{
				ret_loc.set_as_constant(constant_idx);
			}
			else
			{
				ret_loc.set_as_arg(_node->variable_idx);
			}
		}
	}

	return ret_loc;
}

static void jit_expr_x64_build_from_ast(x64_writer_ctx& _writer, ast_node* _node, operand_location _dest)
{
	switch (_node->type)
	{
		case ast_node_type::bin_sub:
		case ast_node_type::bin_add:
		case ast_node_type::bin_mul:
		case ast_node_type::bin_div:
		{
			xmm_reg xmm_reg_to_free = xmm_reg::num_reg;

			operand_location left_op = _dest;
			operand_location right_op;

			ast_node* left_node = _node->binary_op.left;
			ast_node* right_node = _node->binary_op.right;

			if (right_node->is_constant_or_var())
			{
				right_op = load_constant_or_var(_writer, right_node, &xmm_reg_to_free);
			}
			else
			{
				// evaluate right node.
				// TODO: Check variable.
				right_op = _writer.reg_alloc.alloc_reg();
				// TODO: Broken if spill.
				xmm_reg_to_free = right_op.reg;
				jit_expr_x64_build_from_ast(_writer, right_node, right_op);
			}

			jit_expr_x64_build_from_ast(_writer, left_node, _dest);

			switch (_node->type)
			{
				case ast_node_type::bin_sub: x64_subss(_writer, _dest, right_op); break;
				case ast_node_type::bin_add: x64_addss(_writer, _dest, right_op); break;
				case ast_node_type::bin_mul: x64_mulss(_writer, _dest, right_op); break;
				case ast_node_type::bin_div: x64_divss(_writer, _dest, right_op); break;
			}

			if (xmm_reg_to_free != xmm_reg::num_reg)
			{
				_writer.reg_alloc.set_reg_unused(xmm_reg_to_free);
			}
		} break;

		case ast_node_type::un_neg:
		{
			jit_expr_x64_build_from_ast(_writer, _node->unary_op_child, _dest);

			operand_location const_loc;
			const_loc.set_as_constant(_writer.get_constant_index_128(c_sign_bit));
			x64_xorps(_writer, _dest, const_loc);
		} break;

		case ast_node_type::variable:
		{
			operand_location variable_loc;
			variable_loc.set_as_arg(_node->variable_idx);
			x64_movss(_writer, _dest, variable_loc);
		} break;

		case ast_node_type::constant:
		{
			operand_location const_loc;
			const_loc.set_as_constant(_writer.get_constant_index(_node->constant_val));
			x64_movss(_writer, _dest, const_loc);
		} break;

		case ast_node_type::function:
		{
			switch (_node->function.index)
			{
				case builtin_function::abs:
				{
					// TODO: Redundant loads.
					jit_expr_x64_build_from_ast(_writer, _node->function.params[0], _dest);
					operand_location const_loc;
					const_loc.set_as_constant(_writer.get_constant_index_128(c_sign_mask));
					// use andnot to potentially reuse sign bit in a register (need to implement that).
					x64_and_ps(_writer, _dest, const_loc);
				} break;

				case builtin_function::min:
				{
					// TODO: Redundant loads.
					operand_location src_loc = _writer.reg_alloc.alloc_reg();
					jit_expr_x64_build_from_ast(_writer, _node->function.params[0], _dest);
					jit_expr_x64_build_from_ast(_writer, _node->function.params[1], src_loc);
					x64_minss(_writer, _dest, src_loc);
					_writer.reg_alloc.set_reg_unused(src_loc.reg);
				} break;

				case builtin_function::max:
				{
					// TODO: Redundant loads.
					operand_location src_loc = _writer.reg_alloc.alloc_reg();
					jit_expr_x64_build_from_ast(_writer, _node->function.params[0], _dest);
					jit_expr_x64_build_from_ast(_writer, _node->function.params[1], src_loc);
					x64_maxss(_writer, _dest, src_loc);
					_writer.reg_alloc.set_reg_unused(src_loc.reg);
				} break;

				case builtin_function::sqrt: 
				{
					// TODO: Redundant loads.
					jit_expr_x64_build_from_ast(_writer, _node->function.params[0], _dest);
					x64_sqrtss(_writer, _dest, _dest);
				} break;

				case builtin_function::clamp:
				{
					// TODO: Redundant loads.
					operand_location params[2];
					params[0] = _writer.reg_alloc.alloc_reg();
					params[1] = _writer.reg_alloc.alloc_reg();

					jit_expr_x64_build_from_ast(_writer, _node->function.params[0], _dest);
					jit_expr_x64_build_from_ast(_writer, _node->function.params[1], params[0]);
					jit_expr_x64_build_from_ast(_writer, _node->function.params[2], params[1]);

					x64_minss(_writer, _dest, params[1]);
					x64_maxss(_writer, _dest, params[0]);
					_writer.reg_alloc.set_reg_unused(params[0].reg);
					_writer.reg_alloc.set_reg_unused(params[1].reg);
				} break;
			}
		} break;

		default:
		{
			EXPR_JIT_ASSERT(false);
		} break;
	}
}

static void build_constant_usage_info(x64_writer_ctx& _writer, ast_node* _root)
{
	visit_ast_depth_first_post_order(_root, [&_writer](ast_node* _node)
	{
		if (_node->type == ast_node_type::constant)
		{
			uint32_t const idx = _writer.get_constant_index(_node->constant_val);
			++_writer.constants[idx].uses;
		}
		else if (_node->type == ast_node_type::un_neg)
		{
			uint32_t const idx = _writer.get_constant_index_128(c_sign_bit);
			++_writer.constants[idx].uses;
		}
		else if (_node->type == ast_node_type::variable)
		{
			EXPR_JIT_ASSERT(_node->variable_idx < _writer.variables.size);
			++_writer.variables[_node->variable_idx].uses;
		}
	});
}

uint32_t jit_expr_x64(expr const* _expr, void* _buff, uint32_t _buff_size)
{
	EXPR_JIT_ASSERT(_expr);
	EXPR_JIT_ASSERT(_buff);
	
	x64_writer_ctx asm_writer;
	asm_writer.init(_expr, (uint8_t*)_buff, _buff_size);
	build_constant_usage_info(asm_writer, _expr->root);

	operand_location ret_loc;
	ret_loc.set_as_xmm(xmm_reg::xmm0);
	asm_writer.reg_alloc.set_reg_used(xmm_reg::xmm0);

	jit_expr_x64_build_from_ast(asm_writer, _expr->root, ret_loc);
	x64_ret(asm_writer);

	asm_writer.write_constants_and_relocate();

	return asm_writer.bytes_written;
}



} // namespace expr_jit