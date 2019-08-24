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
	dyn_pod_array& operator&(dyn_pod_array const&) = delete;

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
		ensure_cap(size + n);
		T* ptr = mem + size;
		size += n;
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
		return mem[size];
	}

	T* mem = nullptr;
	uint32_t size = 0;
	uint32_t cap = 0;

	alloc_hooks hooks;
};

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

enum class ast_node_type
{
	constant,
	variable,

	bin_add,
	bin_sub,
	bin_mul,
	bin_div,

	un_neg
};

struct ast_node
{
	ast_node_type type;

	union
	{
		float constant_val;
		uint32_t variable_idx;

		struct
		{
			ast_node* left;
			ast_node* right;
		} binary_op;

		ast_node* unary_op_child;
	};
};

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
		if (!chunk_list || chunk_list->next_node == c_nodes_per_chunk)
		{
			chunk* c = (chunk*)_hooks.alloc(_hooks.ctx, sizeof(chunk));
			c->next_chunk = chunk_list;
			chunk_list = c;
			c->next_node = 0;
		}
		return &chunk_list->nodes[chunk_list->next_node++];
	}

	chunk* chunk_list;
};

struct expr
{
	ast_node* alloc_ast_node()
	{
		return node_pool.alloc_node(alloc);
	}

	alloc_hooks alloc;
	ast_node_pool node_pool;

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

	variable,
	constant,

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
		uint32_t variable_idx;
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
					
					switch (sym->type)
					{
						case symbol_type::constant:
						{
							_ctx.peek.type = token_type::constant;
							_ctx.peek.constant_val = sym->constant_val;
						} break;

						case symbol_type::variable:
						{
							_ctx.peek.type = token_type::variable;
							_ctx.peek.variable_idx = sym->variable_idx;
						} break;

						default:
						{
							EXPR_JIT_ASSERT(false);
							return false;
						};
					}

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

static ast_node* parse_factor_ast(parser_ctx& _parser, lexer_ctx& _lexer)
{
	// factor -> [-] constant | variable | (expr)
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
		case token_type::variable:
		{
			lex_next(_lexer);
			factor_node = _parser.expression->alloc_ast_node();
			factor_node->type = ast_node_type::variable;
			factor_node->variable_idx = _lexer.peek.variable_idx;
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

static void optimize_fold_constants(expr* _expr, ast_node* _node)
{
	// Walk depth first post and fold constants.
	switch (_node->type)
	{
		case ast_node_type::bin_add:
		case ast_node_type::bin_sub:
		case ast_node_type::bin_mul:
		case ast_node_type::bin_div:
		{
			ast_node* left_node = _node->binary_op.left;
			ast_node* right_node = _node->binary_op.right;

			optimize_fold_constants(_expr, left_node);
			optimize_fold_constants(_expr, right_node);

			if (_node->binary_op.left->type == ast_node_type::constant
				&& _node->binary_op.right->type == ast_node_type::constant)
			{
				switch (_node->type)
				{
					case ast_node_type::bin_add: _node->constant_val = _node->binary_op.left->constant_val + _node->binary_op.right->constant_val; break;
					case ast_node_type::bin_sub: _node->constant_val = _node->binary_op.left->constant_val - _node->binary_op.right->constant_val; break;
					case ast_node_type::bin_mul: _node->constant_val = _node->binary_op.left->constant_val * _node->binary_op.right->constant_val; break;
					case ast_node_type::bin_div: _node->constant_val = _node->binary_op.left->constant_val / _node->binary_op.right->constant_val; break;
				}

				_node->type = ast_node_type::constant;
			}
			
		} break;

		case ast_node_type::un_neg:
		{
			ast_node* child = _node->unary_op_child;
			optimize_fold_constants(_expr, child);
			if (_node->unary_op_child->type == ast_node_type::constant)
			{
				_node->constant_val = -child->constant_val;
				_node->type = ast_node_type::constant;
			}
		} break;

		default:
		{
		} break;
	}
}

static void optimize_strength_reduction(expr* _expr, ast_node* _node)
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

			optimize_strength_reduction(_expr, left_node);
			optimize_strength_reduction(_expr, right_node);

			if (_node->type == ast_node_type::bin_div)
			{
				// Replace division of constant with multiplication by reciprocal.
				if (_node->binary_op.right->type == ast_node_type::constant)
				{
					_node->binary_op.right->constant_val = 1.0f / _node->binary_op.right->constant_val;
					_node->type = ast_node_type::bin_mul;
				}
			}

		} break;

		case ast_node_type::un_neg:
		{
			optimize_strength_reduction(_expr, _node);
		} break;

		default:
		{
		} break;
	}
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

	expression->root = parse_expr_ast(parser, lexer);
	if (!expression->root)
	{
		free_expression(expression);
		return nullptr;
	}
	
	optimize_fold_constants(expression, expression->root);
	optimize_strength_reduction(expression, expression->root);

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

float eval_node(ast_node const* _node, float const* _args)
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
		return type == operand_type::xmm;;
	}

	operand_type type;

	xmm_reg reg;

	union
	{
		uint32_t constant_idx;
		uint32_t arg_index;
	};
};

struct register_allocator
{
	register_allocator()
	{
		for (bool& b : available_regs)
		{
			b = true;
		}
	}	 

	operand_location alloc_reg()
	{
		for (uint32_t i = 0; i < xmm_reg::num_reg; ++i)
		{
			if (available_regs[i])
			{
				operand_location loc;
				loc.set_as_xmm(xmm_reg(i));
				return loc;
			}
		}

		// TODO:
		EXPR_JIT_ASSERT(false);
	}

	bool available_regs[xmm_reg::num_reg];
};

enum builtin_constants
{
	sign_bit,

	total_constants
};

struct constant_relocation
{
	uint8_t* rip;
	uint8_t* constant_write_loc;
	uint32_t constant_idx;
};

struct x64_writer_ctx
{
	uint32_t get_constant_index(float _constant)
	{
		for (uint32_t i = 0; i < constants.size; ++i)
		{
			if (constants[i] == _constant)
			{
				return i;
			}
		}

		uint32_t const idx = constants.size;
		constants.append(_constant);
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
		uint8_t* reloc_base = buff_cur;
		for (float f : constants)
		{
			uint32_t u;
			memcpy(&u, &f, sizeof(float));
			write_u32(u);
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

	dyn_pod_array<float> constants;
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

static void x64_sse_binary_op(x64_writer_ctx& _writer, operand_location const& _op0, operand_location const& _op1, uint8_t _instruction_prefix)
{
	EXPR_JIT_ASSERT(_op1.is_register());

	// sse prefix first
	_writer.write_u8(x64_prefix::sse_f32);

	uint8_t rex_byte = 0;

	if (operand_requires_rex_prefix(_op0))
	{
		// REX.B
		rex_byte |= 0b0001;
	}

	if (operand_requires_rex_prefix(_op1))
	{
		// REX.R
		rex_byte |= 0b1000;
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
	x64_sse_binary_op(_writer, _dest, _src, 0x59);
}

static void x64_divss(x64_writer_ctx& _writer, operand_location const& _dest, operand_location const& _src)
{
	EXPR_JIT_ASSERT(_dest.is_register());
	x64_sse_binary_op(_writer, _dest, _src, 0x5e);
}

static void x64_addss(x64_writer_ctx& _writer, operand_location const& _dest, operand_location const& _src)
{
	EXPR_JIT_ASSERT(_dest.is_register());
	x64_sse_binary_op(_writer, _src, _dest, 0x58);
}

static void x64_subss(x64_writer_ctx& _writer, operand_location const& _dest, operand_location const& _src)
{
	EXPR_JIT_ASSERT(_dest.is_register());
	x64_sse_binary_op(_writer, _dest, _src, 0x5c);
}

static void x64_ret(x64_writer_ctx& _writer)
{
	_writer.write_u8(0xc3);
}

void jit_expr_x64_build_from_ast(x64_writer_ctx& _writer, ast_node* _node, operand_location _dest)
{
	// Depth first - post order walk AST and generate code.

	switch (_node->type)
	{
		case ast_node_type::bin_sub:
		case ast_node_type::bin_add:
		case ast_node_type::bin_mul:
		case ast_node_type::bin_div:
		{

			//return eval_node(_node->binary_op.left, _args) + eval_node(_node->binary_op.right, _args);
		} break;

		case ast_node_type::un_neg:
		{
			jit_expr_x64_build_from_ast(_writer, _node->unary_op_child->unary_op_child, _dest);
			// Now negate the dest register 
			// pxor reg, [c_sign_bit]
		} break;

		case ast_node_type::variable:
		{
			// TODO: Load to reg.
			_node->variable_idx;
		} break;

		case ast_node_type::constant:
		{
			// TODO: Load constant to reg.
			uint32_t const const_idx = _writer.get_constant_index(_node->constant_val);
		} break;

		default:
		{
			EXPR_JIT_ASSERT(false);
		} break;
	}
}

uint32_t jit_expr_x64(expr const* _expr, uint8_t* _buff, size_t _buff_size)
{
	EXPR_JIT_ASSERT(_expr);
	EXPR_JIT_ASSERT(_buff);
	
	x64_writer_ctx asm_writer;
	asm_writer.init(_expr, _buff, _buff_size);
	operand_location ret_reg;
	ret_reg.set_as_xmm(xmm_reg::xmm0);
	
	operand_location arg;
	arg.set_as_arg(0);

	operand_location const0;
	const0.set_as_constant(asm_writer.get_constant_index(2.0f));

	x64_movss(asm_writer, ret_reg, const0);
	x64_addss(asm_writer, ret_reg, arg);
	x64_ret(asm_writer);
	
	asm_writer.write_constants_and_relocate();

	return asm_writer.bytes_written;
}



} // namespace expr_jit