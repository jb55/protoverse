
#include "wasm.h"
#include "parser.h"
#include "debug.h"
#include "error.h"

#include <unistd.h>
#include <stdarg.h>
#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>

#define interp_error(p, fmt, ...) note_error(&((p)->errors), interp_codeptr(p), fmt, ##__VA_ARGS__)
#define parse_err(p, fmt, ...) note_error(&((p)->errs), &(p)->cur, fmt, ##__VA_ARGS__)

#ifdef NOINLINE
  #define INLINE __attribute__((noinline))
#else
  #define INLINE inline
#endif

#define ERR_STACK_SIZE 16
#define NUM_LOCALS 0xFFFF
#define WASM_PAGE_SIZE 65536

static const int MAX_LABELS = 256;

static int interp_code(struct wasm_interp *interp);

struct expr_parser {
	struct wasm_interp *interp; // optional...
	struct cursor *code;
	struct errors *errs;
	struct cursor *stack; // optional
};

static INLINE struct callframe *top_callframe(struct cursor *cur)
{
	return (struct callframe*)cursor_top(cur, sizeof(struct callframe));
}

static INLINE struct cursor *interp_codeptr(struct wasm_interp *interp)
{
	struct callframe *frame;
	if (unlikely(!(frame = top_callframe(&interp->callframes))))
		return 0;
	return &frame->code;
}

static INLINE int cursor_popval(struct cursor *cur, struct val *val)
{
	return cursor_pop(cur, (unsigned char*)val, sizeof(*val));
}

static const char *valtype_name(enum valtype valtype)
{
	switch (valtype) {
	case val_i32: return "i32";
	case val_i64: return "i64";
	case val_f32: return "f32";
	case val_f64: return "f64";
	case val_ref_null: return "null";
	case val_ref_func: return "func";
	case val_ref_extern: return "extern";
	}

	return "?";
}

static const char *reftype_name(enum reftype reftype) {
	return valtype_name((enum valtype)reftype);
}

static const char *valtype_literal(enum valtype valtype)
{
	switch (valtype) {
	case val_i32: return "";
	case val_i64: return "L";
	case val_f32: return "";
	case val_f64: return "f";
	case val_ref_null: return "null";
	case val_ref_func: return "func";
	case val_ref_extern: return "extern";
	}

	return "?";
}

static INLINE int is_valid_fn_index(struct module *module, u32 ind)
{
	return ind < module->num_funcs;
}

static INLINE struct func *get_function(struct module *module, u32 ind)
{
	if (unlikely(!is_valid_fn_index(module, ind)))
		return NULL;
	return &module->funcs[ind];
}

static struct val *get_fn_local(struct wasm_interp *interp, int fn, u32 ind)
{
	struct func *func;

	if (unlikely(!(func = get_function(interp->module, fn)))) {
		interp_error(interp, "unknown fn %d", fn);
		return NULL;
	}

	if (unlikely(ind >= func->num_locals)) {
		interp_error(interp, "local index %d too high for %s:%d (max %d)",
				ind, func->name, fn, func->num_locals-1);
		return NULL;
	}

	return &func->locals[ind].val;
}

static struct val *get_local(struct wasm_interp *interp, u32 ind)
{
	struct callframe *frame;

	if (unlikely(!(frame = top_callframe(&interp->callframes)))) {
		interp_error(interp, "no callframe?");
		return NULL;
	}

	return get_fn_local(interp, frame->fn, ind);
}

static INLINE int stack_popval(struct wasm_interp *interp, struct val *val)
{
	return cursor_popval(&interp->stack, val);
}

static INLINE struct val *cursor_topval(struct cursor *stack)
{
	return (struct val *)cursor_top(stack, sizeof(struct val));
}

static INLINE struct val *stack_topval(struct wasm_interp *interp)
{
	return cursor_topval(&interp->stack);
}

static INLINE int cursor_pop_i32(struct cursor *stack, int *i)
{
	struct val val;
	if (unlikely(!cursor_popval(stack, &val)))
		return 0;
	if (unlikely(val.type != val_i32))
		return 0;
	*i = val.num.i32;
	return 1;
}

static INLINE int cursor_pop_i64(struct cursor *stack, int64_t *i)
{
	struct val val;
	if (unlikely(!cursor_popval(stack, &val)))
		return 0;
	if (unlikely(val.type != val_i64))
		return 0;
	*i = val.num.i64;
	return 1;
}


static int is_reftype(enum valtype type)
{
	switch (type) {
	case val_i32:
	case val_i64:
	case val_f32:
	case val_f64:
		return 0;
	case val_ref_null:
	case val_ref_func:
	case val_ref_extern:
		return 1;
	}
	return 0;
}

/*
static INLINE int cursor_pop_ref(struct cursor *stack, struct val *val)
{
	if (!cursor_popval(stack, val)) {
		return 0;
	}
	if (!is_reftype(val->type)) {
		return 0;
	}
	return 1;
}
*/

static INLINE int stack_pop_ref(struct wasm_interp *interp, struct val *val)
{
	if (!cursor_popval(&interp->stack, val)) {
		return interp_error(interp, "no value on stack");
	}
	if (!is_reftype(val->type)) {
		return interp_error(interp, "not a reftype, got %s",
				valtype_name(val->type));
	}
	return 1;
}

static INLINE int stack_pop_i32(struct wasm_interp *interp, int *i)
{
	return cursor_pop_i32(&interp->stack, i);
}

static INLINE int stack_pop_i64(struct wasm_interp *interp, int64_t *i)
{
	return cursor_pop_i64(&interp->stack, i);
}

static INLINE int cursor_pop_valtype(struct cursor *stack, enum valtype type,
		struct val *val)
{
	if (unlikely(!cursor_popval(stack, val))) {
		return 0;
	}

	if (unlikely(val->type != type)) {
		return 0;
	}

	return 1;
}

static INLINE int stack_pop_valtype(struct wasm_interp *interp,
		enum valtype type, struct val *val)
{
	return cursor_pop_valtype(&interp->stack, type, val);
}

static void print_val(struct val *val)
{
	switch (val->type) {
	case val_i32: printf("%d", val->num.i32); break;
	case val_i64: printf("%" PRId64, val->num.i64); break;
	case val_f32: printf("%f", val->num.f32); break;
	case val_f64: printf("%f", val->num.f64); break;

	case val_ref_null:
		      break;
	case val_ref_func:
	case val_ref_extern:
		      printf("%d", val->ref.addr);
		      break;
	}
	printf("%s", valtype_literal(val->type));
}

#ifdef DEBUG
static void print_refval(struct refval *ref, enum reftype reftype)
{
	struct val val;
	val.type = (enum valtype)reftype;
	val.ref = *ref;
	print_val(&val);
}
#endif

static void print_stack(struct cursor *stack)
{
	struct val val;
	int i;
	u8 *p = stack->p;

	if (stack->p == stack->start) {
		return;
	}

	for (i = 0; stack->p > stack->start; i++) {
		cursor_popval(stack, &val);
		printf("[%d] ", i);
		print_val(&val);
		printf("\n");
	}

	stack->p = p;
}

static INLINE int cursor_pushval(struct cursor *cur, struct val *val)
{
	return cursor_push(cur, (u8*)val, sizeof(*val));
}

static INLINE int cursor_push_i32(struct cursor *stack, int i)
{
	struct val val;
	val.type = val_i32;
	val.num.i32 = i;

	return cursor_pushval(stack, &val);
}

static INLINE int cursor_push_funcref(struct cursor *stack, int addr)
{
	struct val val;
	val.type = val_ref_func;
	val.ref.addr = addr;
	return cursor_pushval(stack, &val);
}

static INLINE int stack_push_i32(struct wasm_interp *interp, int i)
{
	return cursor_push_i32(&interp->stack, i);
}

static INLINE void make_i32_val(struct val *val, int v)
{
	val->type = val_i32;
	val->num.i32 = v;
}

static INLINE int stack_pushval(struct wasm_interp *interp, struct val *val)
{
	return cursor_pushval(&interp->stack, val);
}

static int interp_exit(struct wasm_interp *interp)
{
	interp->quitting = 1;
	return 0;
}

static int builtin_proc_exit(struct wasm_interp *interp)
{
	return interp_exit(interp);
}

static int builtin_get_args_sizes(struct wasm_interp *interp);
static int builtin_get_args(struct wasm_interp *interp);
static int builtin_fd_write(struct wasm_interp *interp);

static struct builtin BUILTINS[] = {
	{ .name = "args_get",       .fn = builtin_get_args },
	{ .name = "fd_write",       .fn = builtin_fd_write },
	{ .name = "args_sizes_get", .fn = builtin_get_args_sizes },
	{ .name = "proc_exit",      .fn = builtin_proc_exit  },
};

static const int NUM_BUILTINS = sizeof(BUILTINS) / sizeof(*BUILTINS);

static int parse_instr(struct expr_parser *parser, u8 tag, struct instr *op);

static INLINE int is_valtype(unsigned char byte)
{
	switch ((enum valtype)byte) {
		case val_i32: // i32
		case val_i64: // i64
		case val_f32: // f32
		case val_f64: // f64
		case val_ref_func: // funcref
		case val_ref_null: // null
		case val_ref_extern: // externref
			return 1;
	}

	return 0;
}


/*
static int sizeof_valtype(enum valtype valtype)
{
	switch (valtype) {
	case i32: return 4;
	case f32: return 4;
	case i64: return 8;
	case f64: return 8;
	}

	return 0;
}
*/

static char *instr_name(enum instr_tag tag)
{
	static char unk[6] = {0};

	switch (tag) {
		case i_unreachable: return "unreachable";
		case i_nop: return "nop";
		case i_block: return "block";
		case i_loop: return "loop";
		case i_if: return "if";
		case i_else: return "else";
		case i_end: return "end";
		case i_br: return "br";
		case i_br_if: return "br_if";
		case i_br_table: return "br_table";
		case i_return: return "return";
		case i_call: return "call";
		case i_call_indirect: return "call_indirect";
		case i_drop: return "drop";
		case i_select: return "select";
		case i_local_get: return "local_get";
		case i_local_set: return "local_set";
		case i_local_tee: return "local_tee";
		case i_global_get: return "global_get";
		case i_global_set: return "global_set";
		case i_i32_load: return "i32_load";
		case i_i64_load: return "i64_load";
		case i_f32_load: return "f32_load";
		case i_f64_load: return "f64_load";
		case i_i32_load8_s: return "i32_load8_s";
		case i_i32_load8_u: return "i32_load8_u";
		case i_i32_load16_s: return "i32_load16_s";
		case i_i32_load16_u: return "i32_load16_u";
		case i_i64_load8_s: return "i64_load8_s";
		case i_i64_load8_u: return "i64_load8_u";
		case i_i64_load16_s: return "i64_load16_s";
		case i_i64_load16_u: return "i64_load16_u";
		case i_i64_load32_s: return "i64_load32_s";
		case i_i64_load32_u: return "i64_load32_u";
		case i_i32_store: return "i32_store";
		case i_i64_store: return "i64_store";
		case i_f32_store: return "f32_store";
		case i_f64_store: return "f64_store";
		case i_i32_store8: return "i32_store8";
		case i_i32_store16: return "i32_store16";
		case i_i64_store8: return "i64_store8";
		case i_i64_store16: return "i64_store16";
		case i_i64_store32: return "i64_store32";
		case i_memory_size: return "memory_size";
		case i_memory_grow: return "memory_grow";
		case i_i32_const: return "i32_const";
		case i_i64_const: return "i64_const";
		case i_f32_const: return "f32_const";
		case i_f64_const: return "f64_const";
		case i_i32_eqz: return "i32_eqz";
		case i_i32_eq: return "i32_eq";
		case i_i32_ne: return "i32_ne";
		case i_i32_lt_s: return "i32_lt_s";
		case i_i32_lt_u: return "i32_lt_u";
		case i_i32_gt_s: return "i32_gt_s";
		case i_i32_gt_u: return "i32_gt_u";
		case i_i32_le_s: return "i32_le_s";
		case i_i32_le_u: return "i32_le_u";
		case i_i32_ge_s: return "i32_ge_s";
		case i_i32_ge_u: return "i32_ge_u";
		case i_i64_eqz: return "i64_eqz";
		case i_i64_eq: return "i64_eq";
		case i_i64_ne: return "i64_ne";
		case i_i64_lt_s: return "i64_lt_s";
		case i_i64_lt_u: return "i64_lt_u";
		case i_i64_gt_s: return "i64_gt_s";
		case i_i64_gt_u: return "i64_gt_u";
		case i_i64_le_s: return "i64_le_s";
		case i_i64_le_u: return "i64_le_u";
		case i_i64_ge_s: return "i64_ge_s";
		case i_i64_ge_u: return "i64_ge_u";
		case i_f32_eq: return "f32_eq";
		case i_f32_ne: return "f32_ne";
		case i_f32_lt: return "f32_lt";
		case i_f32_gt: return "f32_gt";
		case i_f32_le: return "f32_le";
		case i_f32_ge: return "f32_ge";
		case i_f64_eq: return "f64_eq";
		case i_f64_ne: return "f64_ne";
		case i_f64_lt: return "f64_lt";
		case i_f64_gt: return "f64_gt";
		case i_f64_le: return "f64_le";
		case i_f64_ge: return "f64_ge";
		case i_i32_clz: return "i32_clz";
		case i_i32_add: return "i32_add";
		case i_i32_sub: return "i32_sub";
		case i_i32_mul: return "i32_mul";
		case i_i32_div_s: return "i32_div_s";
		case i_i32_div_u: return "i32_div_u";
		case i_i32_rem_s: return "i32_rem_s";
		case i_i32_rem_u: return "i32_rem_u";
		case i_i32_and: return "i32_and";
		case i_i32_or: return "i32_or";
		case i_i32_xor: return "i32_xor";
		case i_i32_shl: return "i32_shl";
		case i_i32_shr_s: return "i32_shr_s";
		case i_i32_shr_u: return "i32_shr_u";
		case i_i32_rotl: return "i32_rotl";
		case i_i32_rotr: return "i32_rotr";
		case i_i64_clz: return "i64_clz";
		case i_i64_ctz: return "i64_ctz";
		case i_i64_popcnt: return "i64_popcnt";
		case i_i64_add: return "i64_add";
		case i_i64_sub: return "i64_sub";
		case i_i64_mul: return "i64_mul";
		case i_i64_div_s: return "i64_div_s";
		case i_i64_div_u: return "i64_div_u";
		case i_i64_rem_s: return "i64_rem_s";
		case i_i64_rem_u: return "i64_rem_u";
		case i_i64_and: return "i64_and";
		case i_i64_or: return "i64_or";
		case i_i64_xor: return "i64_xor";
		case i_i64_shl: return "i64_shl";
		case i_i64_shr_s: return "i64_shr_s";
		case i_i64_shr_u: return "i64_shr_u";
		case i_i64_rotl: return "i64_rotl";
		case i_i64_rotr: return "i64_rotr";
		case i_f32_abs: return "f32_abs";
		case i_f32_neg: return "f32_neg";
		case i_f32_ceil: return "f32_ceil";
		case i_f32_floor: return "f32_floor";
		case i_f32_trunc: return "f32_trunc";
		case i_f32_nearest: return "f32_nearest";
		case i_f32_sqrt: return "f32_sqrt";
		case i_f32_add: return "f32_add";
		case i_f32_sub: return "f32_sub";
		case i_f32_mul: return "f32_mul";
		case i_f32_div: return "f32_div";
		case i_f32_min: return "f32_min";
		case i_f32_max: return "f32_max";
		case i_f32_copysign: return "f32_copysign";
		case i_f64_abs: return "f64_abs";
		case i_f64_neg: return "f64_neg";
		case i_f64_ceil: return "f64_ceil";
		case i_f64_floor: return "f64_floor";
		case i_f64_trunc: return "f64_trunc";
		case i_f64_nearest: return "f64_nearest";
		case i_f64_sqrt: return "f64_sqrt";
		case i_f64_add: return "f64_add";
		case i_f64_sub: return "f64_sub";
		case i_f64_mul: return "f64_mul";
		case i_f64_div: return "f64_div";
		case i_f64_min: return "f64_min";
		case i_f64_max: return "f64_max";
		case i_f64_copysign: return "f64_copysign";
		case i_i32_wrap_i64: return "i32_wrap_i64";
		case i_i32_trunc_f32_s: return "i32_trunc_f32_s";
		case i_i32_trunc_f32_u: return "i32_trunc_f32_u";
		case i_i32_trunc_f64_s: return "i32_trunc_f64_s";
		case i_i32_trunc_f64_u: return "i32_trunc_f64_u";
		case i_i64_extend_i32_s: return "i64_extend_i32_s";
		case i_i64_extend_i32_u: return "i64_extend_i32_u";
		case i_i64_trunc_f32_s: return "i64_trunc_f32_s";
		case i_i64_trunc_f32_u: return "i64_trunc_f32_u";
		case i_i64_trunc_f64_s: return "i64_trunc_f64_s";
		case i_i64_trunc_f64_u: return "i64_trunc_f64_u";
		case i_f32_convert_i32_s: return "f32_convert_i32_s";
		case i_f32_convert_i32_u: return "f32_convert_i32_u";
		case i_f32_convert_i64_s: return "f32_convert_i64_s";
		case i_f32_convert_i64_u: return "f32_convert_i64_u";
		case i_f32_demote_f64: return "f32_demote_f64";
		case i_f64_convert_i32_s: return "f64_convert_i32_s";
		case i_f64_convert_i32_u: return "f64_convert_i32_u";
		case i_f64_convert_i64_s: return "f64_convert_i64_s";
		case i_f64_convert_i64_u: return "f64_convert_i64_u";
		case i_f64_promote_f32: return "f64_promote_f32";
		case i_i32_reinterpret_f32: return "i32_reinterpret_f32";
		case i_i64_reinterpret_f64: return "i64_reinterpret_f64";
		case i_f32_reinterpret_i32: return "f32_reinterpret_i32";
		case i_f64_reinterpret_i64: return "f64_reinterpret_i64";
		case i_i32_extend8_s: return "i32_extend8_s";
		case i_i32_extend16_s: return "i32_extend16_s";
		case i_i64_extend8_s: return "i64_extend8_s";
		case i_i64_extend16_s: return "i64_extend16_s";
		case i_i64_extend32_s: return "i64_extend32_s";
		case i_ref_null: return "ref_null";
		case i_ref_func: return "ref_func";
		case i_ref_is_null: return "ref_is_null";
		case i_table_op: return "table_op";
		case i_table_get: return "table_get";
		case i_table_set: return "table_set";
		case i_selects: return "selects";
	}

	snprintf(unk, sizeof(unk), "0x%02x", tag);
	return unk;
}

static INLINE int was_section_parsed(struct module *module,
	enum section_tag section)
{
	if (section == section_custom)
		return module->custom_sections > 0;

	return module->parsed & (1 << section);
}

static INLINE int cursor_push_callframe(struct cursor *cur, struct callframe *frame)
{
	//debug("pushing callframe %d fn:%d\n", ++callframe_cnt, frame->fn);
	return cursor_push(cur, (u8*)frame, sizeof(*frame));
}

static INLINE int cursor_drop_callframe(struct cursor *cur)
{
	//debug("dropping callframe %d fn:%d\n", callframe_cnt--, top_callframe(cur)->fn);
	return cursor_drop(cur, sizeof(struct callframe));
}

static INLINE int cursor_dropval(struct cursor *stack)
{
	return cursor_drop(stack, sizeof(struct val));
}

static INLINE int cursor_popint(struct cursor *cur, int *i)
{
	return cursor_pop(cur, (u8 *)i, sizeof(int));
}


void print_error_backtrace(struct errors *errors)
{
	struct cursor errs;
	struct error err;

	copy_cursor(&errors->cur, &errs);
	errs.p = errs.start;

	while (errs.p < errors->cur.p) {
		if (!cursor_pull_error(&errs, &err)) {
			printf("backtrace: couldn't pull error\n");
			return;
		}
		printf("%08x:%s\n", err.pos, err.msg);
	}
}

static void _functype_str(struct functype *ft, struct cursor *buf)
{
	u32 i;

	cursor_push_str(buf, "(");

	for (i = 0; i < ft->params.num_valtypes; i++) {
		cursor_push_str(buf, valtype_name(ft->params.valtypes[i]));

		if (i != ft->params.num_valtypes-1) {
			cursor_push_str(buf, ", ");
		}
	}

	cursor_push_str(buf, ") -> (");

	for (i = 0; i < ft->result.num_valtypes; i++) {
		cursor_push_str(buf, valtype_name(ft->result.valtypes[i]));

		if (i != ft->result.num_valtypes-1) {
			cursor_push_str(buf, ", ");
		}
	}

	cursor_push_c_str(buf, ")");
}

static const char *functype_str(struct functype *ft, char *buf, int buflen)
{
	struct cursor cur;
	if (buflen == 0)
		return "";

	buf[buflen-1] = 0;
	make_cursor((u8*)buf, (u8*)buf + buflen-1, &cur);

	_functype_str(ft, &cur);

	return (const char*)buf;
}

static void print_functype(struct functype *ft)
{
	static char buf[0xFF];
	printf("%s\n", functype_str(ft, buf, sizeof(buf)));
}

static void print_type_section(struct typesec *typesec)
{
	u32 i;
	printf("%d functypes:\n", typesec->num_functypes);
	for (i = 0; i < typesec->num_functypes; i++) {
		printf("    ");
		print_functype(&typesec->functypes[i]);
	}
}

static void print_func_section(struct funcsec *funcsec)
{
	printf("%d functions\n", funcsec->num_indices);
	/*
	printf("    ");
	for (i = 0; i < funcsec->num_indices; i++) {
		printf("%d ", funcsec->type_indices[i]);
	}
	printf("\n");
	*/
}

__attribute__((unused))
static const char *exportdesc_name(enum exportdesc desc)
{
	switch (desc) {
		case export_func: return "function";
		case export_table: return "table";
		case export_mem: return "memory";
		case export_global: return "global";
	}

	return "unknown";
}

static void print_import(struct import *import)
{
	(void)import;
	printf("%s %s\n", import->module_name, import->name);
}

static void print_import_section(struct importsec *importsec)
{
	u32 i;
	printf("%d imports:\n", importsec->num_imports);
	for (i = 0; i < importsec->num_imports; i++) {
		printf("    ");
		print_import(&importsec->imports[i]);
	}
}

static void print_limits(struct limits *limits)
{
	switch (limits->type) {
	case limit_min:
		printf("%d", limits->min);
		break;
	case limit_min_max:
		printf("%d-%d", limits->min, limits->max);
		break;
	}
}

static void print_memory_section(struct memsec *memory)
{
	u32 i;
	struct limits *mem;

	printf("%d memory:\n", memory->num_mems);
	for (i = 0; i < memory->num_mems; i++) {
		mem = &memory->mems[i];
		printf("    ");
		print_limits(mem);
		printf("\n");
	}
}

static void print_table_section(struct tablesec *section)
{
	u32 i;
	struct table *table;

	printf("%d tables:\n", section->num_tables);
	for (i = 0; i < section->num_tables; i++) {
		table = &section->tables[i];
		printf("    ");
		printf("%s: ", reftype_name(table->reftype));
		print_limits(&table->limits);
		printf("\n");
	}
}

static int count_imports(struct module *module, enum import_type *typ)
{
	u32 i, count = 0;
	struct import *import;
	struct importsec *imports;

	if (!was_section_parsed(module, section_import))
		return 0;

	imports = &module->import_section;

	if (typ == NULL)
		return imports->num_imports;

	for (i = 0; i < imports->num_imports; i++) {
		import = &imports->imports[i];
		if (import->desc.type == *typ) {
			count++;
		}
	}

	return count;
}

static INLINE int count_imported_functions(struct module *module)
{
	enum import_type typ = import_func;
	return count_imports(module, &typ);
}

static INLINE const char *get_function_name(struct module *module, int fn)
{
	struct func *func = NULL;
	if (unlikely(!(func = get_function(module, fn)))) {
		return "unknown";
	}
	return func->name;
}

static void print_element_section(struct elemsec *section)
{
	printf("%d elements\n", section->num_elements);
}

static void print_start_section(struct module *module)
{
	u32 fn = module->start_section.start_fn;
	printf("start function: %d <%s>\n", fn, get_function_name(module, fn));
}

static void print_export_section(struct exportsec *exportsec)
{
	u32 i;
	printf("%d exports:\n", exportsec->num_exports);
	for (i = 0; i < exportsec->num_exports; i++) {
		printf("    ");
		printf("%s %s %d\n", exportdesc_name(exportsec->exports[i].desc),
				exportsec->exports[i].name,
				exportsec->exports[i].index);
	}
}

/*
static void print_local(struct local *local)
{
	debug("%d %s\n", local->n, valtype_name(local->valtype));
}

static void print_func(struct wasm_func *func)
{
	int i;

	debug("func locals (%d): \n", func->num_locals);
	for (i = 0; i < func->num_locals; i++) {
		print_local(&func->locals[i]);
	}
	debug("%d bytes of code\n", func->code_len);
}
*/

static void print_global_section(struct globalsec *section)
{
	printf("%d globals\n", section->num_globals);
}


static void print_code_section(struct codesec *codesec)
{
	printf("%d code segments\n", codesec->num_funcs);
	/*
	for (i = 0; i < codesec->num_funcs; i++) {
		print_func(&codesec->funcs[i]);
	}
	*/
}

static void print_data_section(struct datasec *section)
{
	printf("%d data segments\n", section->num_datas);
}

static void print_custom_section(struct customsec *section)
{
	printf("custom (%s) %d bytes\n", section->name, section->data_len);
}

static void print_section(struct module *module, enum section_tag section)
{
	u32 i;

	switch (section) {
	case section_custom:
		for (i = 0; i < module->custom_sections; i++) {
			print_custom_section(&module->custom_section[i]);
		}
		break;
	case section_type:
		print_type_section(&module->type_section);
		break;
	case section_import:
		print_import_section(&module->import_section);
		break;
	case section_function:
		print_func_section(&module->func_section);
		break;
	case section_table:
		print_table_section(&module->table_section);
		break;
	case section_memory:
		print_memory_section(&module->memory_section);
		break;
	case section_global:
		print_global_section(&module->global_section);
		break;
	case section_export:
		print_export_section(&module->export_section);
		break;
	case section_start:
		print_start_section(module);
		break;
	case section_element:
		print_element_section(&module->element_section);
		break;
	case section_code:
		print_code_section(&module->code_section);
		break;
	case section_data:
		print_data_section(&module->data_section);
		break;
	case num_sections:
		assert(0);
		break;
	}
}

static void print_module(struct module *module)
{
	u32 i;
	enum section_tag section;

	for (i = 0; i < num_sections; i++) {
		section = (enum section_tag)i;
		if (was_section_parsed(module, section)) {
			print_section(module, section);
		}
	}
}


static int leb128_write(struct cursor *write, unsigned int value)
{
	unsigned char byte;
	while (1) {
		byte = value & 0x7F;
		value >>= 7;
		if (value == 0) {
			if (!cursor_push_byte(write, byte))
				return 0;
			return 1;
		} else {
			if (!cursor_push_byte(write, byte | 0x80))
				return 0;
		}
	}
}

#define BYTE_AT(type, i, shift) (((type)(p[i]) & 0x7f) << (shift))
#define LEB128_1(type) (BYTE_AT(type, 0, 0))
#define LEB128_2(type) (BYTE_AT(type, 1, 7) | LEB128_1(type))
#define LEB128_3(type) (BYTE_AT(type, 2, 14) | LEB128_2(type))
#define LEB128_4(type) (BYTE_AT(type, 3, 21) | LEB128_3(type))
#define LEB128_5(type) (BYTE_AT(type, 4, 28) | LEB128_4(type))

static INLINE int read_i64(struct cursor *read, int64_t *val)
{
	int64_t shift;
	u8 byte;

	*val = 0;
	shift = 0;

	do {
		if (!pull_byte(read, &byte))
			return 0;
		*val |= ((byte & 0x7F) << shift);
		shift += 7;
	} while ((byte & 0x80) != 0);

	/* sign bit of byte is second high-order bit (0x40) */
	if ((shift < 64) && (byte & 0x40))
		*val |= (~0 << shift);

	return 1;
}

static INLINE int uleb128_read(struct cursor *read, unsigned int *val)
{
	unsigned int shift = 0;
	u8 byte;
	*val = 0;

	for (;;) {
		if (!pull_byte(read, &byte))
			return 0;

		*val |= (0x7F & byte) << shift;

		if ((0x80 & byte) == 0)
			break;

		shift += 7;
	}

	return 1;
}

static INLINE int sleb128_read(struct cursor *read, signed int *val)
{
	int shift;
	u8 byte;

	*val = 0;
	shift = 0;

	do {
		if (!pull_byte(read, &byte))
			return 0;
		*val |= ((byte & 0x7F) << shift);
		shift += 7;
	} while ((byte & 0x80) != 0);

	/* sign bit of byte is second high-order bit (0x40) */
	if ((shift < 32) && (byte & 0x40))
		*val |= (0xFFFFFFFF << shift);

	return 1;
}

/*
static INLINE int uleb128_read(struct cursor *read, unsigned int *val)
{
	unsigned char p[6] = {0};
	*val = 0;

	if (pull_byte(read, &p[0]) && (p[0] & 0x80) == 0) {
		*val = LEB128_1(unsigned int);
		if (p[0] == 0x7F)
			assert((int)*val == -1);
		return 1;
	} else if (pull_byte(read, &p[1]) && (p[1] & 0x80) == 0) {
		*val = LEB128_2(unsigned int);
		return 2;
	} else if (pull_byte(read, &p[2]) && (p[2] & 0x80) == 0) {
		*val = LEB128_3(unsigned int);
		return 3;
	} else if (pull_byte(read, &p[3]) && (p[3] & 0x80) == 0) {
		*val = LEB128_4(unsigned int);
		return 4;
	} else if (pull_byte(read, &p[4]) && (p[4] & 0x80) == 0) {
		if (!(p[4] & 0xF0)) {
			*val = LEB128_5(unsigned int);
			return 5;
		}
		//printf("%02X & 0xF0\n", p[4] & 0xF0);
	}

	return 0;
}
*/

static INLINE int read_int(struct cursor *read, int *val)
{
	return sleb128_read(read, val);
}


static INLINE int read_u32(struct cursor *read, u32 *val)
{
	return uleb128_read(read, val);
}


static int parse_section_tag(struct cursor *cur, enum section_tag *section)
{
	unsigned char byte;
	unsigned char *start;
	assert(section);

	start = cur->p;

	if (!pull_byte(cur, &byte)) {
		return 0;
	}

	if (byte >= num_sections) {
		cur->p = start;
		return 0;
	}

	*section = (enum section_tag)byte;
	return 1;
}

static int parse_valtype(struct wasm_parser *p, enum valtype *valtype)
{
	unsigned char *start;

	start = p->cur.p;

	if (unlikely(!pull_byte(&p->cur, (unsigned char*)valtype))) {
		return parse_err(p, "valtype tag oob");
	}

	if (unlikely(!is_valtype((unsigned char)*valtype))) {
		cursor_print_around(&p->cur, 10);
		p->cur.p = start;
		return parse_err(p, "0x%02x is not a valid valtype tag", *valtype);
	}

	return 1;
}

static int parse_result_type(struct wasm_parser *p, struct resulttype *rt)
{
	u32 i, elems;
	enum valtype valtype;
	unsigned char *start;

	rt->num_valtypes = 0;
	rt->valtypes = 0;
	start = p->mem.p;

	if (unlikely(!read_u32(&p->cur, &elems))) {
		parse_err(p, "vec len");
		return 0;
	}

	for (i = 0; i < elems; i++)
	{
		if (unlikely(!parse_valtype(p, &valtype))) {
			parse_err(p, "valtype #%d", i);
			p->mem.p = start;
			return 0;
		}

		if (unlikely(!cursor_push_byte(&p->mem, (unsigned char)valtype))) {
			parse_err(p, "valtype push data OOM #%d", i);
			p->mem.p = start;
			return 0;
		}
	}

	rt->num_valtypes = elems;
	rt->valtypes = start;

	return 1;
}


static int parse_func_type(struct wasm_parser *p, struct functype *func)
{
	if (unlikely(!consume_byte(&p->cur, FUNC_TYPE_TAG))) {
		parse_err(p, "type tag");
		return 0;
	}

	if (unlikely(!parse_result_type(p, &func->params))) {
		parse_err(p, "params");
		return 0;
	}

	if (unlikely(!parse_result_type(p, &func->result))) {
		parse_err(p, "result");
		return 0;
	}

	return 1;
}

static int parse_name(struct wasm_parser *p, const char **name)
{
	u32 bytes;
	if (unlikely(!read_u32(&p->cur, &bytes))) {
		parse_err(p, "name len");
		return 0;
	}

	if (unlikely(!pull_data_into_cursor(&p->cur, &p->mem, (unsigned char**)name,
				bytes))) {
		parse_err(p, "name string");
		return 0;
	}

	if (unlikely(!cursor_push_byte(&p->mem, 0))) {
		parse_err(p, "name null byte");
		return 0;
	}

	return 1;
}

static int parse_export_desc(struct wasm_parser *p, enum exportdesc *desc)
{
	unsigned char byte;

	if (!pull_byte(&p->cur, &byte)) {
		parse_err(p, "export desc byte eof");
		return 0;
	}

	switch((enum exportdesc)byte) {
	case export_func:
	case export_table:
	case export_mem:
	case export_global:
		*desc = (enum exportdesc)byte;
		return 1;
	}

	parse_err(p, "invalid tag: %x", byte);
	return 0;
}

static int parse_export(struct wasm_parser *p, struct wexport *export)
{
	if (!parse_name(p, &export->name)) {
		parse_err(p, "export name");
		return 0;
	}

	if (!parse_export_desc(p, &export->desc)) {
		parse_err(p, "export desc");
		return 0;
	}

	if (!read_u32(&p->cur, &export->index)) {
		parse_err(p, "export index");
		return 0;
	}

	return 1;
}

static int parse_local(struct wasm_parser *p, struct local *local)
{
	if (unlikely(!read_u32(&p->cur, &local->val.num.u32))) {
		debug("fail parse local\n");
		return parse_err(p, "n");
	}

	if (unlikely(!parse_valtype(p, &local->val.type))) {
		debug("fail parse valtype\n");
		return parse_err(p, "valtype");
	}

	return 1;
}

static int parse_vector(struct wasm_parser *p, int item_size,
			u32 *elems, void **items)
{
	if (!read_u32(&p->cur, elems)) {
		return parse_err(p, "len");
	}

	*items = cursor_alloc(&p->mem, *elems * item_size);

	if (*items == NULL) {
		parse_err(p, "vector alloc oom");
		return 0;
	}

	return 1;
}

static int parse_func(struct wasm_parser *p, struct wasm_func *func)
{
	struct local *locals;
	u32 i, size;
	u8 *start;

	if (!read_u32(&p->cur, &size)) {
		return parse_err(p, "code size");
	}

	start = p->cur.p;
	locals = (struct local*)p->mem.p;

	if (!read_u32(&p->cur, &func->num_locals)) {
		return parse_err(p, "read locals vec");
	}

	if (!cursor_alloc(&p->mem, sizeof(*locals) * func->num_locals)) {
		return parse_err(p, "oom alloc param locals");
	}

	if (p->cur.p > p->cur.end) {
		return parse_err(p, "corrupt functype?");
	}

	for (i = 0; i < func->num_locals; i++) {
		if (!parse_local(p, &locals[i])) {
			return parse_err(p, "local #%d", i);
		}
	}

	func->locals = locals;
	func->code.code_len = size - (p->cur.p - start);

	if (!pull_data_into_cursor(&p->cur, &p->mem, &func->code.code,
				func->code.code_len)) {
		return parse_err(p, "code oom");
	}

	if (!(func->code.code[func->code.code_len-1] == i_end)) {
		return parse_err(p, "no end tag (corruption?)");
	}

	return 1;
}

static INLINE int count_internal_functions(struct module *module)
{
	return !was_section_parsed(module, section_code) ? 0 :
		module->code_section.num_funcs;
}


static int parse_code_section(struct wasm_parser *p,
		struct codesec *code_section)
{
	struct wasm_func *funcs;
	u32 i;

	if (!parse_vector(p, sizeof(*funcs), &code_section->num_funcs,
			  (void**)&funcs)) {
		return parse_err(p, "funcs");
	}

	for (i = 0; i < code_section->num_funcs; i++) {
		if (!parse_func(p, &funcs[i])) {
			return parse_err(p, "func #%d", i);
		}
	}

	code_section->funcs = funcs;

	return 1;
}

static int is_valid_reftype(unsigned char reftype)
{
	switch ((enum reftype)reftype) {
		case funcref: return 1;
		case externref: return 1;
	}
	return 0;
}

static int parse_reftype(struct wasm_parser *p, enum reftype *reftype)
{
	u8 tag;

	if (!pull_byte(&p->cur, &tag)) {
		parse_err(p, "reftype");
		return 0;
	}

	if (!is_valid_reftype(tag)) {
		cursor_print_around(&p->cur, 10);
		parse_err(p, "invalid reftype: 0x%02x", tag);
		return 0;
	}

	*reftype = (enum reftype)tag;

	return 1;
}


static int parse_export_section(struct wasm_parser *p,
		struct exportsec *export_section)
{
	struct wexport *exports;
	u32 elems, i;

	if (!parse_vector(p, sizeof(*exports), &elems, (void**)&exports)) {
		parse_err(p, "vector");
		return 0;
	}

	for (i = 0; i < elems; i++) {
		if (!parse_export(p, &exports[i])) {
			parse_err(p, "export #%d", i);
			return 0;
		}
	}

	export_section->num_exports = elems;
	export_section->exports = exports;

	return 1;
}

static int parse_limits(struct wasm_parser *p, struct limits *limits)
{
	unsigned char tag;
	if (!pull_byte(&p->cur, &tag)) {
		return parse_err(p, "oob");
	}

	if (tag != limit_min && tag != limit_min_max) {
		return parse_err(p, "invalid tag %02x", tag);
	}

	if (!read_u32(&p->cur, &limits->min)) {
		return parse_err(p, "min");
	}

	if (tag == limit_min)
		return 1;

	if (!read_u32(&p->cur, &limits->max)) {
		return parse_err(p, "max");
	}

	return 1;
}

static int parse_table(struct wasm_parser *p, struct table *table)
{
	if (!parse_reftype(p, &table->reftype)) {
		return parse_err(p, "reftype");
	}

	if (!parse_limits(p, &table->limits)) {
		return parse_err(p, "limits");
	}

	return 1;
}

static int parse_mut(struct wasm_parser *p, enum mut *mut)
{
	if (consume_byte(&p->cur, mut_const)) {
		*mut = mut_const;
		return 1;
	}

	if (consume_byte(&p->cur, mut_var)) {
		*mut = mut_var;
		return 1;
	}

	return parse_err(p, "unknown mut %02x", *p->cur.p);
}

static int parse_globaltype(struct wasm_parser *p, struct globaltype *g)
{
	if (!parse_valtype(p, &g->valtype)) {
		return parse_err(p, "valtype");
	}

	return parse_mut(p, &g->mut);
}

static INLINE void make_expr_parser(struct errors *errs, struct cursor *code,
		struct expr_parser *p)
{
	p->interp = NULL;
	p->code = code;
	p->errs = errs;
	p->stack = NULL;
}

/*
static void print_code(u8 *code, int code_len)
{
	struct cursor c;
	struct expr_parser parser;
	struct errors errs;
	struct instr op;
	u8 tag;

	errs.enabled = 0;

	make_expr_parser(&errs, &c, &parser);
	make_cursor(code, code + code_len, &c);

	for (;;) {
		if (!pull_byte(&c, &tag)) {
			break;
		}

		printf("%s ", instr_name(tag));

		if (!parse_instr(&parser, tag, &op)) {
			break;
		}
	}

	printf("\n");
}
*/

static inline int is_const_instr(u8 tag)
{
	switch ((enum const_instr)tag) {
	case ci_global_get:
	case ci_ref_null:
	case ci_ref_func:
	case ci_const_i32:
	case ci_const_i64:
	case ci_const_f32:
	case ci_end:
	case ci_const_f64:
		return 1;
	}
	return 0;
}

static int cursor_push_nullval(struct cursor *stack)
{
	struct val val;
	val.type = val_ref_null;
	return cursor_pushval(stack, &val);
}

static const char *show_instr(struct instr *instr)
{
	struct cursor buf;
	static char buffer[64];
	static char tmp[32];
	int len, i;

	buffer[sizeof(buffer)-1] = 0;
	make_cursor((u8*)buffer, (u8*)buffer + sizeof(buffer) - 1, &buf);

	cursor_push_str(&buf, instr_name(instr->tag));
	len = buf.p - buf.start;

	for (i = 0; i < 14-len; i++)
		cursor_push_byte(&buf, ' ');

	switch (instr->tag) {
		// two-byte instrs
		case i_memory_size:
		case i_memory_grow:
			sprintf(tmp, "0x%02x", instr->memidx);
			cursor_push_str(&buf, tmp);
			break;

		case i_block:
		case i_loop:
		case i_if:
			break;

		case i_else:
		case i_end:
			break;

		case i_call:
		case i_local_get:
		case i_local_set:
		case i_local_tee:
		case i_global_get:
		case i_global_set:
		case i_br:
		case i_br_if:
		case i_i32_const:
		case i_i64_const:
		case i_ref_func:
		case i_table_set:
		case i_table_get:
			sprintf(tmp, "%d", instr->i32);
			cursor_push_str(&buf, tmp);
			break;

		case i_ref_null:
			sprintf(tmp, "%s", reftype_name(instr->reftype));
			cursor_push_str(&buf, tmp);
			break;


		case i_i32_load:
		case i_i64_load:
		case i_f32_load:
		case i_f64_load:
		case i_i32_load8_s:
		case i_i32_load8_u:
		case i_i32_load16_s:
		case i_i32_load16_u:
		case i_i64_load8_s:
		case i_i64_load8_u:
		case i_i64_load16_s:
		case i_i64_load16_u:
		case i_i64_load32_s:
		case i_i64_load32_u:
		case i_i32_store:
		case i_i64_store:
		case i_f32_store:
		case i_f64_store:
		case i_i32_store8:
		case i_i32_store16:
		case i_i64_store8:
		case i_i64_store16:
		case i_i64_store32:
			sprintf(tmp, "%d %d", instr->memarg.offset, instr->memarg.align);
			cursor_push_str(&buf, tmp);
			break;

		case i_selects:
			break;

		case i_br_table:
			break;

		case i_call_indirect:
			sprintf(tmp, "%d %d", instr->call_indirect.typeidx,
					instr->call_indirect.tableidx);
			cursor_push_str(&buf, tmp);
			break;

		case i_f32_const:
			sprintf(tmp, "%f", instr->fp_single);
			cursor_push_str(&buf, tmp);
			break;

		case i_f64_const:
			sprintf(tmp, "%f", instr->fp_double);
			cursor_push_str(&buf, tmp);
			break;

		// single-tag ops
		case i_unreachable:
		case i_nop:
		case i_return:
		case i_drop:
		case i_select:
		case i_i32_eqz:
		case i_i32_eq:
		case i_i32_ne:
		case i_i32_lt_s:
		case i_i32_lt_u:
		case i_i32_gt_s:
		case i_i32_gt_u:
		case i_i32_le_s:
		case i_i32_le_u:
		case i_i32_ge_s:
		case i_i32_ge_u:
		case i_i64_eqz:
		case i_i64_eq:
		case i_i64_ne:
		case i_i64_lt_s:
		case i_i64_lt_u:
		case i_i64_gt_s:
		case i_i64_gt_u:
		case i_i64_le_s:
		case i_i64_le_u:
		case i_i64_ge_s:
		case i_i64_ge_u:
		case i_f32_eq:
		case i_f32_ne:
		case i_f32_lt:
		case i_f32_gt:
		case i_f32_le:
		case i_f32_ge:
		case i_f64_eq:
		case i_f64_ne:
		case i_f64_lt:
		case i_f64_gt:
		case i_f64_le:
		case i_f64_ge:
		case i_i32_clz:
		case i_i32_add:
		case i_i32_sub:
		case i_i32_mul:
		case i_i32_div_s:
		case i_i32_div_u:
		case i_i32_rem_s:
		case i_i32_rem_u:
		case i_i32_and:
		case i_i32_or:
		case i_i32_xor:
		case i_i32_shl:
		case i_i32_shr_s:
		case i_i32_shr_u:
		case i_i32_rotl:
		case i_i32_rotr:
		case i_i64_clz:
		case i_i64_ctz:
		case i_i64_popcnt:
		case i_i64_add:
		case i_i64_sub:
		case i_i64_mul:
		case i_i64_div_s:
		case i_i64_div_u:
		case i_i64_rem_s:
		case i_i64_rem_u:
		case i_i64_and:
		case i_i64_or:
		case i_i64_xor:
		case i_i64_shl:
		case i_i64_shr_s:
		case i_i64_shr_u:
		case i_i64_rotl:
		case i_i64_rotr:
		case i_f32_abs:
		case i_f32_neg:
		case i_f32_ceil:
		case i_f32_floor:
		case i_f32_trunc:
		case i_f32_nearest:
		case i_f32_sqrt:
		case i_f32_add:
		case i_f32_sub:
		case i_f32_mul:
		case i_f32_div:
		case i_f32_min:
		case i_f32_max:
		case i_f32_copysign:
		case i_f64_abs:
		case i_f64_neg:
		case i_f64_ceil:
		case i_f64_floor:
		case i_f64_trunc:
		case i_f64_nearest:
		case i_f64_sqrt:
		case i_f64_add:
		case i_f64_sub:
		case i_f64_mul:
		case i_f64_div:
		case i_f64_min:
		case i_f64_max:
		case i_f64_copysign:
		case i_i32_wrap_i64:
		case i_i32_trunc_f32_s:
		case i_i32_trunc_f32_u:
		case i_i32_trunc_f64_s:
		case i_i32_trunc_f64_u:
		case i_i64_extend_i32_s:
		case i_i64_extend_i32_u:
		case i_i64_trunc_f32_s:
		case i_i64_trunc_f32_u:
		case i_i64_trunc_f64_s:
		case i_i64_trunc_f64_u:
		case i_f32_convert_i32_s:
		case i_f32_convert_i32_u:
		case i_f32_convert_i64_s:
		case i_f32_convert_i64_u:
		case i_f32_demote_f64:
		case i_f64_convert_i32_s:
		case i_f64_convert_i32_u:
		case i_f64_convert_i64_s:
		case i_f64_convert_i64_u:
		case i_f64_promote_f32:
		case i_i32_reinterpret_f32:
		case i_i64_reinterpret_f64:
		case i_f32_reinterpret_i32:
		case i_f64_reinterpret_i64:
		case i_i32_extend8_s:
		case i_i32_extend16_s:
		case i_i64_extend8_s:
		case i_i64_extend16_s:
		case i_i64_extend32_s:
		case i_ref_is_null:
		case i_table_op:
			break;
	}

	cursor_push_byte(&buf, 0);
	return buffer;
}

static int eval_const_instr(struct instr *instr, struct errors *errs,
		struct cursor *stack)
{
	//debug("eval_const_instr %s\n", show_instr(instr));

	switch ((enum const_instr)instr->tag) {
	case ci_global_get:
		return note_error(errs, stack, "todo: global_get inside global");
	case ci_ref_null:
		if (unlikely(!cursor_push_nullval(stack))) {
			return note_error(errs, stack, "couldn't push null");
		}
		return 1;
	case ci_ref_func:
		if (unlikely(!cursor_push_funcref(stack, instr->i32))) {
			return note_error(errs, stack, "couldn't push funcref");
		}
		return 1;
	case ci_const_i32:
		if (unlikely(!cursor_push_i32(stack, instr->i32))) {
			return note_error(errs, stack,
					"global push i32 const");
		}
		return 1;
	case ci_const_i64:
		return note_error(errs, stack, "todo: global push const i64");
	case ci_const_f32:
		return note_error(errs, stack, "todo: global push const f32");
	case ci_end:
		return note_error(errs, stack, "unexpected end tag");
	case ci_const_f64:
		return note_error(errs, stack, "todo: global push const f64");
	}

	return note_error(errs, stack, "non-const expr instr %s",
			instr_name(instr->tag));
}

static int parse_const_expr(struct expr_parser *p, struct expr *expr)
{
	u8 tag;
	struct instr instr;

	expr->code = p->code->p;

	while (1) {
		if (unlikely(!pull_byte(p->code, &tag))) {
			return note_error(p->errs, p->code, "oob");
		}

		if (unlikely(!is_const_instr(tag))) {
			return note_error(p->errs, p->code,
					"invalid const expr instruction: '%s'",
					instr_name(tag));
		}

		if (tag == i_end) {
			expr->code_len = p->code->p - expr->code;
			return 1;
		}

		if (unlikely(!parse_instr(p, tag, &instr))) {
			return note_error(p->errs, p->code,
					"couldn't parse const expr instr '%s'",
					instr_name(tag));
		}

		if (p->stack &&
		    unlikely(!eval_const_instr(&instr, p->errs, p->stack))) {
			return note_error(p->errs, p->code, "eval const instr");
		}
	}

	return 0;
}

static INLINE void make_const_expr_evaluator(struct errors *errs,
		struct cursor *code, struct cursor *stack,
		struct expr_parser *parser)
{
	parser->interp = NULL;
	parser->stack = stack;
	parser->code = code;
	parser->errs = errs;
}

static INLINE void make_const_expr_parser(struct wasm_parser *p,
		struct expr_parser *parser)
{
	parser->interp = NULL;
	parser->stack = NULL;
	parser->code = &p->cur;
	parser->errs = &p->errs;
}

static INLINE int eval_const_expr(struct expr *expr, struct errors *errs,
		struct cursor *stack)
{
	struct cursor code;
	struct expr expr_out;
	struct expr_parser parser;

	make_cursor(expr->code, expr->code + expr->code_len, &code);
	make_const_expr_evaluator(errs, &code, stack, &parser);

	return parse_const_expr(&parser, &expr_out);
}

static INLINE int eval_const_val(struct expr *expr, struct errors *errs,
		struct cursor *stack, struct val *val)
{
	if (!eval_const_expr(expr, errs, stack)) {
		return note_error(errs, stack, "eval const expr");
	}

	if (!cursor_popval(stack, val)) {
		return note_error(errs, stack, "no val to pop?");
	}

	if (cursor_dropval(stack))  {
		return note_error(errs, stack, "stack not empty");
	}

	return 1;
}


static int parse_global(struct wasm_parser *p,
		struct global *global)
{
	struct expr_parser parser;
	struct cursor stack;

	stack.start = p->mem.p;
	stack.p = p->mem.p;
	stack.end = p->mem.end;

	make_const_expr_evaluator(&p->errs, &p->cur, &stack, &parser);

	if (!parse_globaltype(p, &global->type)) {
		return parse_err(p, "type");
	}

	if (!parse_const_expr(&parser, &global->init)) {
		return parse_err(p, "init code");
	}

	if (!cursor_popval(&stack, &global->val)) {
		return parse_err(p, "couldn't eval global expr");
	}

	return 1;
}

static int parse_global_section(struct wasm_parser *p,
		struct globalsec *global_section)
{
	struct global *globals;
	u32 elems, i;

	if (!parse_vector(p, sizeof(*globals), &elems, (void**)&globals)) {
		return parse_err(p, "globals vector");
	}

	for (i = 0; i < elems; i++) {
		if (!parse_global(p, &globals[i])) {
			return parse_err(p, "global #%d/%d", i+1, elems);
		}
	}

	global_section->num_globals = elems;
	global_section->globals = globals;

	return 1;
}

static INLINE void make_interp_expr_parser(struct wasm_interp *interp,
		struct expr_parser *p)
{
	assert(interp);

	p->interp = interp;
	p->code = interp_codeptr(interp);
	p->errs = &interp->errors;

	assert(p->code);
}

static int parse_instrs_until(struct expr_parser *p, u8 stop_instr,
               u8 **parsed_instrs, u32 *instr_len)
{
       u8 tag;
       struct instr op;

       *parsed_instrs = p->code->p;
       *instr_len = 0;

       //debug("parse_instrs_until starting\n");
       for (;;) {
               if (!pull_byte(p->code, &tag))
                       return note_error(p->errs, p->code, "oob");

	       if ((tag != i_if && tag == stop_instr) ||
		   (stop_instr == i_if && (tag == i_else || tag == i_end))) {
		       //debug("parse_instrs_until ending\n");
		       *instr_len = p->code->p - *parsed_instrs;
                       return 1;
               }

		debug("%04lX parsing instr %s (0x%02x)\n",
			p->code->p - 1 - p->code->start, instr_name(tag), tag);
               if (!parse_instr(p, tag, &op)) {
                       return note_error(p->errs, p->code,
			  "parse %s instr (0x%x)", instr_name(tag), tag);
	       }

       }
}

static int parse_expr(struct wasm_parser *p, struct expr *expr)
{
	struct expr_parser parser;

	make_expr_parser(&p->errs, &p->cur, &parser);

	if (!parse_instrs_until(&parser, i_end, &expr->code, &expr->code_len))
		return parse_err(p, "instrs");

	return 1;
}

static int parse_elem_func_inits(struct wasm_parser *p, struct elem *elem)
{
	u32 index, i;
	struct expr *expr;

	if (!read_u32(&p->cur, &elem->num_inits))
		return parse_err(p, "func indices vec read fail");

	if (!(elem->inits = cursor_alloc(&p->mem, elem->num_inits *
					 sizeof(struct expr)))) {
		return parse_err(p, "couldn't alloc vec(funcidx) for elem");
	}

	for (i = 0; i < elem->num_inits; i++) {
		expr = &elem->inits[i];
		expr->code = p->mem.p;

		if (!read_u32(&p->cur, &index))
			return parse_err(p, "func index %d read fail", i);
		if (!cursor_push_byte(&p->mem, i_ref_func))
			return parse_err(p, "push ref_func instr oob for %d", i);
		if (!leb128_write(&p->mem, index))
			return parse_err(p, "push ref_func u32 index oob for %d", i);
		if (!cursor_push_byte(&p->mem, i_end))
			return parse_err(p, "push i_end for init %d", i);

		expr->code_len = p->mem.p - expr->code;
	}

	return 1;
}


static int parse_element(struct wasm_parser *p, struct elem *elem)
{
	u8 tag = 0;
	(void)elem;

	if (!pull_byte(&p->cur, &tag))
		return parse_err(p, "tag");

	if (tag > 7)
		return parse_err(p, "expected tag 0x00 to 0x07, got 0x%02x", tag);

	switch (tag) {
	case 0x00:
		if (!parse_expr(p, &elem->offset))
			return parse_err(p, "elem 0x00 offset expr");

		// func inits
		if (!parse_elem_func_inits(p, elem))
			return parse_err(p, "generate func index exprs");

		elem->mode = elem_mode_active;
		elem->tableidx = 0;
		elem->reftype = funcref;
		break;

	default:
		return parse_err(p, "implement parse element 0x%02x", tag);
	}

	return 1;
}

static int parse_custom_section(struct wasm_parser *p, u32 size,
		struct customsec *section)
{
	u8 *start;
	start = p->cur.p;

	if (p->module.custom_sections + 1 > MAX_CUSTOM_SECTIONS)
		return parse_err(p, "more than 32 custom sections!");

	if (!parse_name(p, &section->name))
		return parse_err(p, "name");

	section->data = p->cur.p;
	section->data_len = size - (p->cur.p - start);
	p->cur.p += section->data_len;
	p->module.custom_sections++;

	return 1;
}

static int parse_element_section(struct wasm_parser *p, struct elemsec *elemsec)
{
	struct elem *elements;
	u32 count, i;

	if (!parse_vector(p, sizeof(struct elem), &count, (void**)&elements))
		return parse_err(p, "elements vec");

	for (i = 0; i < count; i++) {
		if (!parse_element(p, &elements[i]))
			return parse_err(p, "element %d of %d", i+1, count);
	}

	elemsec->num_elements = count;
	elemsec->elements = elements;

	return 1;
}

static int parse_memory_section(struct wasm_parser *p,
		struct memsec *memory_section)
{
	struct limits *mems;
	u32 elems, i;

	if (!parse_vector(p, sizeof(*mems), &elems, (void**)&mems)) {
		return parse_err(p, "mems vector");
	}

	for (i = 0; i < elems; i++) {
		if (!parse_limits(p, &mems[i])) {
			return parse_err(p, "memory #%d/%d", i+1, elems);
		}
	}

	memory_section->num_mems = elems;
	memory_section->mems = mems;

	return 1;
}

static int parse_start_section(struct wasm_parser *p,
		struct startsec *start_section)
{
	if (!read_u32(&p->cur, &start_section->start_fn)) {
		return parse_err(p, "start_fn index");
	}

	return 1;
}

static INLINE int parse_byte_vector(struct wasm_parser *p, u8 **data,
		u32 *data_len)
{
	if (!read_u32(&p->cur, data_len)) {
		return parse_err(p, "len");
	}

	if (p->cur.p + *data_len > p->cur.end) {
		return parse_err(p, "byte vector overflow");
	}

	*data = p->cur.p;
	p->cur.p += *data_len;

	return 1;
}

static int parse_wdata(struct wasm_parser *p, struct wdata *data)
{
	struct expr_parser parser;
	u8 tag;

	if (!pull_byte(&p->cur, &tag)) {
		return parse_err(p, "tag");
	}

	if (tag > 2) {
		cursor_print_around(&p->cur, 10);
		return parse_err(p, "invalid datasegment tag: 0x%x", tag);
	}

	make_const_expr_parser(p, &parser);

	switch (tag) {
	case 0:
		data->mode = datamode_active;
		data->active.mem_index = 0;

		if (!parse_const_expr(&parser, &data->active.offset_expr)) {
			return parse_err(p, "const expr");
		}

		if (!parse_byte_vector(p, &data->bytes, &data->bytes_len)) {
			return parse_err(p, "bytes vector");
		}

		break;

	case 1:
		data->mode = datamode_passive;

		if (!parse_byte_vector(p, &data->bytes, &data->bytes_len)) {
			return parse_err(p, "passive bytes vector");
		}

		break;

	case 2:
		data->mode = datamode_active;

		if (!read_u32(&p->cur, &data->active.mem_index))  {
			return parse_err(p, "read active data mem_index");
		}

		if (!parse_const_expr(&parser, &data->active.offset_expr)) {
			return parse_err(p, "read active data (w/ mem_index) offset_expr");
		}

		if (!parse_byte_vector(p, &data->bytes, &data->bytes_len)) {
			return parse_err(p, "active (w/ mem_index) bytes vector");
		}

		break;
	}

	return 1;
}

static int parse_data_section(struct wasm_parser *p, struct datasec *section)
{
	struct wdata *data;
	u32 elems, i;

	if (!parse_vector(p, sizeof(*data), &elems, (void**)&data)) {
		return parse_err(p, "datas vector");
	}

	for (i = 0; i < elems; i++) {
		if (!parse_wdata(p, &data[i])) {
			return parse_err(p, "data segment #%d/%d", i+1, elems);
		}
	}

	section->num_datas = elems;
	section->datas = data;

	return 1;
}

static int parse_table_section(struct wasm_parser *p,
		struct tablesec *table_section)
{
	struct table *tables;
	u32 elems, i;

	if (!parse_vector(p, sizeof(*tables), &elems, (void**)&tables)) {
		return parse_err(p, "tables vector");
	}

	for (i = 0; i < elems; i++) {
		if (!parse_table(p, &tables[i])) {
			parse_err(p, "table #%d/%d", i+1, elems);
			return 0;
		}
	}

	table_section->num_tables = elems;
	table_section->tables = tables;

	return 1;
}

static int parse_function_section(struct wasm_parser *p,
		struct funcsec *funcsec)
{
	u32 i, elems, *indices;

	if (!parse_vector(p, sizeof(*indices), &elems, (void**)&indices)) {
		return parse_err(p, "indices");
	}

	for (i = 0; i < elems; i++) {
		if (!read_u32(&p->cur, &indices[i])) {
			parse_err(p, "typeidx #%d", i);
			return 0;
		}
	}

	funcsec->type_indices = indices;
	funcsec->num_indices = elems;

	return 1;
}

static int parse_import_table(struct wasm_parser *p, struct limits *limits)
{
	if (!consume_byte(&p->cur, 0x70)) {
		parse_err(p, "elemtype != 0x70");
		return 0;
	}

	if (!parse_limits(p, limits)) {
		parse_err(p, "limits");
		return 0;
	}

	return 1;
}

static int parse_importdesc(struct wasm_parser *p, struct importdesc *desc)
{
	u8 tag;

	if (!pull_byte(&p->cur, &tag)) {
		parse_err(p, "oom");
		return 0;
	}

	desc->type = (enum import_type)tag;

	switch (desc->type) {
	case import_func:
		if (!read_u32(&p->cur, &desc->typeidx)) {
			parse_err(p, "typeidx");
			return 0;
		}

		return 1;

	case import_table:
		return parse_import_table(p, &desc->tabletype);

	case import_mem:
		if (!parse_limits(p, &desc->memtype)) {
			parse_err(p, "memtype limits");
			return 0;
		}

		return 1;

	case import_global:
		if (!parse_globaltype(p, &desc->globaltype)) {
			parse_err(p, "globaltype");
			return 0;
		}

		return 1;
	}

	parse_err(p, "unknown importdesc tag %02x", tag);
	return 0;
}

static int find_builtin(const char *name)
{
	struct builtin *b;
	u32 i;

	for (i = 0; i < NUM_BUILTINS; i++) {
		b = &BUILTINS[i];
		if (!strcmp(b->name, name))
			return i;
	}
	return -1;
}

static int parse_import(struct wasm_parser *p, struct import *import)
{
	import->resolved_builtin = -1;

	if (!parse_name(p, &import->module_name))
		return parse_err(p, "module name");

	if (!parse_name(p, &import->name))
		return parse_err(p, "name");

	if (!parse_importdesc(p, &import->desc))
		return parse_err(p, "desc");

	if (import->desc.type == import_func) {
		import->resolved_builtin =
			find_builtin(import->name);
	}

	return 1;
}

static int parse_import_section(struct wasm_parser *p, struct importsec *importsec)
{
	u32 elems, i;
	struct import *imports;

	if (!parse_vector(p, sizeof(*imports), &elems, (void**)&imports)) {
		return parse_err(p, "imports");
	}

	for (i = 0; i < elems; i++) {
		if (!parse_import(p, &imports[i])) {
			return parse_err(p, "import #%d", i);
		}
	}

	importsec->imports = imports;
	importsec->num_imports = elems;

	return 1;
}

/* type section is just a vector of function types */
static int parse_type_section(struct wasm_parser *p, struct typesec *typesec)
{
	u32 elems, i;
	struct functype *functypes;

	typesec->num_functypes = 0;
	typesec->functypes = NULL;

	if (!parse_vector(p, sizeof(*functypes), &elems, (void**)&functypes)) {
		parse_err(p, "functypes");
		return 0;
	}

	for (i = 0; i < elems; i++) {
		if (!parse_func_type(p, &functypes[i])) {
			parse_err(p, "functype #%d", i);
			return 0;
		}
	}

	typesec->functypes = functypes;
	typesec->num_functypes = elems;

	return 1;
}

static int parse_section_by_tag(struct wasm_parser *p, enum section_tag tag,
				u32 size)
{
	(void)size;
	switch (tag) {
	case section_custom:
		if (!parse_custom_section(p, size,
			&p->module.custom_section[p->module.custom_sections]))
			return parse_err(p, "custom section");
		return 1;
	case section_type:
		if (!parse_type_section(p, &p->module.type_section)) {
			return parse_err(p, "type section");
		}
		return 1;
	case section_import:
		if (!parse_import_section(p, &p->module.import_section)) {
			return parse_err(p, "import section");
		}
		return 1;
	case section_function:
		if (!parse_function_section(p, &p->module.func_section)) {
			return parse_err(p, "function section");
		}
		return 1;
	case section_table:
		if (!parse_table_section(p, &p->module.table_section)) {
			return parse_err(p, "table section");
		}
		return 1;
	case section_memory:
		if (!parse_memory_section(p, &p->module.memory_section)) {
			return parse_err(p, "memory section");
		}
		return 1;
	case section_global:
		if (!parse_global_section(p, &p->module.global_section)) {
			return parse_err(p, "global section");
		}
		return 1;
	case section_export:
		if (!parse_export_section(p, &p->module.export_section)) {
			return parse_err(p, "export section");
		}
		return 1;
	case section_start:
		if (!parse_start_section(p, &p->module.start_section)) {
			return parse_err(p, "start section");
		}
		return 1;

	case section_element:
		if (!parse_element_section(p, &p->module.element_section)) {
			return parse_err(p, "element section");
		}
		return 1;

	case section_code:
		if (!parse_code_section(p, &p->module.code_section)) {
			return parse_err(p, "code section");
		}
		return 1;

	case section_data:
		if (!parse_data_section(p, &p->module.data_section)) {
			return parse_err(p, "data section");
		}
		return 1;

	default:
		return parse_err(p, "invalid section tag");
	}

	return 1;
}

static const char *section_name(enum section_tag tag)
{
	switch (tag) {
		case section_custom:
			return "custom";
		case section_type:
			return "type";
		case section_import:
			return "import";
		case section_function:
			return "function";
		case section_table:
			return "table";
		case section_memory:
			return "memory";
		case section_global:
			return "global";
		case section_export:
			return "export";
		case section_start:
			return "start";
		case section_element:
			return "element";
		case section_code:
			return "code";
		case section_data:
			return "data";
		default:
			return "invalid";
	}

}

static int parse_section(struct wasm_parser *p)
{
	enum section_tag tag;
	struct section;
	u32 bytes;

	if (!parse_section_tag(&p->cur, &tag)) {
		parse_err(p, "section tag");
		return 2;
	}

	if (!read_u32(&p->cur, &bytes)) {
		return parse_err(p, "section len");
	}

	if (!parse_section_by_tag(p, tag, bytes)) {
		return parse_err(p, "%s (%d bytes)", section_name(tag), bytes);
	}

	p->module.parsed |= 1 << tag;

	return 1;
}

static struct builtin *builtin_func(u32 ind)
{
	if (unlikely(ind >= NUM_BUILTINS)) {
		printf("UNUSUAL: invalid builtin index %d (max %d)\n", ind,
				NUM_BUILTINS-1);
		return NULL;
	}
	return &BUILTINS[ind];
}

static const char *find_exported_function_name(struct module *module, u32 fn)
{
	u32 i;
	struct wexport *export;

	if (!was_section_parsed(module, section_export))
		return "unknown";

	for (i = 0; i < module->export_section.num_exports; i++) {
		export = &module->export_section.exports[i];
		if (export->desc == export_func &&
		    export->index == fn) {
			return export->name;
		}
	}

	return "unknown";
}


static int make_func_lookup_table(struct wasm_parser *parser)
{
	u32 i, num_imports, num_func_imports, num_internal_funcs, typeidx, fn;
	struct import *import;
	struct importsec *imports;
	struct func *func;

	fn = 0;

	imports = &parser->module.import_section;
	num_func_imports = count_imported_functions(&parser->module);
	num_internal_funcs = count_internal_functions(&parser->module);
	parser->module.num_funcs = num_func_imports + num_internal_funcs;

	if (!(parser->module.funcs =
		cursor_alloc(&parser->mem, sizeof(struct func) *
			     parser->module.num_funcs))) {
		return parse_err(parser, "oom");
	}

	/* imports */
	num_imports = count_imports(&parser->module, NULL);

	for (i = 0; i < num_imports; i++) {
		import = &imports->imports[i];

		if (import->desc.type != import_func)
			continue;

		func = &parser->module.funcs[fn++];

		func->name = import->name;
		typeidx = import->desc.typeidx;
		func->functype = &parser->module.type_section.functypes[typeidx];
		func->type = func_type_builtin;

		if (import->resolved_builtin == -1) {
			debug("warning: %s not resolved\n", func->name);
			func->builtin = NULL;
		} else {
			func->builtin = builtin_func(import->resolved_builtin);
		}
	}

	/* module fns */
	for (i = 0; i < num_internal_funcs; i++, fn++) {
		func = &parser->module.funcs[fn];

		typeidx = parser->module.func_section.type_indices[i];
		func->type = func_type_wasm;
		func->wasm_func = &parser->module.code_section.funcs[i];
		func->functype = &parser->module.type_section.functypes[typeidx];
		func->name = find_exported_function_name(&parser->module, fn);
	}

	assert(fn == parser->module.num_funcs);

	return 1;
}


int parse_wasm(struct wasm_parser *p)
{
	p->module.parsed = 0;
	p->module.custom_sections = 0;

	if (!consume_bytes(&p->cur, WASM_MAGIC, sizeof(WASM_MAGIC))) {
		parse_err(p, "magic");
		goto fail;
	}

	if (!consume_u32(&p->cur, WASM_VERSION)) {
		parse_err(p, "version");
		goto fail;
	}

	while (1) {
		if (cursor_eof(&p->cur))
			break;

		if (!parse_section(p)) {
			parse_err(p, "section");
			goto fail;
		}
	}

	if (!make_func_lookup_table(p)) {
		return parse_err(p, "failed making func lookup table");
	}

	//print_module(&p->module);
	debug("module parse success!\n\n");
	return 1;

fail:
	debug("\npartially parsed module:\n");
	print_module(&p->module);
	debug("parse failure backtrace:\n");
	print_error_backtrace(&p->errs);
	return 0;
}

static INLINE int interp_prep_binop(struct wasm_interp *interp, struct val *lhs,
		struct val *rhs, struct val *c, enum valtype typ)
{
	c->type = typ;

	if (!cursor_popval(&interp->stack, rhs)) {
		return interp_error(interp, "couldn't pop first val");
	}

	if (!cursor_popval(&interp->stack, lhs)) {
		return interp_error(interp, "couldn't pop second val");
	}

	if (lhs->type != typ || rhs->type != typ) {
	        return interp_error(interp, "type mismatch, %s != %s",
			valtype_name(lhs->type), valtype_name(rhs->type));
	}

	return 1;
}

static int interp_i32_add(struct wasm_interp *interp)
{
	struct val a, b, c;

	if (!interp_prep_binop(interp, &a, &b, &c, val_i32)) {
		interp_error(interp, "add prep");
		return 0;
	}

	c.num.i32 = a.num.i32 + b.num.i32;

	return stack_pushval(interp, &c);
}

static int interp_i32_sub(struct wasm_interp *interp)
{
	struct val a, b, c;

	if (!interp_prep_binop(interp, &a, &b, &c, val_i32)) {
		interp_error(interp, "sub prep");
		return 0;
	}

	c.num.i32 = a.num.i32 - b.num.i32;

	return stack_pushval(interp, &c);
}

static INLINE int set_fn_local(struct wasm_interp *interp, int fn, u32 ind,
			       struct val *val)
{
	struct val *local;

	if (unlikely(!(local = get_fn_local(interp, fn, ind)))) {
		return interp_error(interp, "no local?");
	}

	memcpy(local, val, sizeof(*val));

	return 1;
}

static INLINE int set_local(struct wasm_interp *interp, u32 ind,
			    struct val *val)
{
	struct callframe *frame;

	if (unlikely(!(frame = top_callframe(&interp->callframes)))) {
		return interp_error(interp, "no callframe?");
	}

	return set_fn_local(interp, frame->fn, ind, val);
}

static INLINE int interp_local_tee(struct wasm_interp *interp, u32 index)
{
	struct val *val;

	if (unlikely(!(val = stack_topval(interp)))) {
		return interp_error(interp, "pop");
	}

	if (unlikely(!set_local(interp, index, val))) {
		return interp_error(interp, "set local");
	}

	return 1;
}

static int interp_local_set(struct wasm_interp *interp, u32 index)
{
	struct val val;

	if (unlikely(!interp_local_tee(interp, index))) {
		return interp_error(interp, "tee set");
	}

	if (unlikely(!stack_popval(interp, &val))) {
		return interp_error(interp, "pop");
	}

	return 1;
}

static INLINE int interp_local_get(struct wasm_interp *interp, u32 index)
{
	struct val *val;

	if (unlikely(!(val = get_local(interp, index)))) {
		return interp_error(interp, "get local");
	}

	return stack_pushval(interp, val);
}

static INLINE void make_i64_val(struct val *val, u64 v)
{
	val->type = val_i64;
	val->num.i64 = v;
}

static INLINE int interp_i32_lt_s(struct wasm_interp *interp)
{
	struct val lhs, rhs, c;
	if (unlikely(!interp_prep_binop(interp, &lhs, &rhs, &c, val_i32))) {
		return interp_error(interp, "binop prep");
	}
	c.num.i32 = (signed int)lhs.num.i32 < (signed int)rhs.num.i32;
	return stack_pushval(interp, &c);
}

static INLINE int interp_i32_lt_u(struct wasm_interp *interp)
{
	struct val lhs, rhs, c;
	if (unlikely(!interp_prep_binop(interp, &lhs, &rhs, &c, val_i32))) {
		return interp_error(interp, "binop prep");
	}
	c.num.i32 = (unsigned int)lhs.num.i32 < (unsigned int)rhs.num.i32;
	return stack_pushval(interp, &c);
}

static INLINE int interp_i32_le_u(struct wasm_interp *interp)
{
	struct val lhs, rhs, c;
	if (unlikely(!interp_prep_binop(interp, &lhs, &rhs, &c, val_i32)))
		return interp_error(interp, "binop prep");
	c.num.i32 = (unsigned int)lhs.num.i32 <= (unsigned int)rhs.num.i32;
	return stack_pushval(interp, &c);
}

static INLINE int interp_i32_gt_s(struct wasm_interp *interp)
{
	struct val lhs, rhs, c;
	if (unlikely(!interp_prep_binop(interp, &lhs, &rhs, &c, val_i32)))
		return interp_error(interp, "binop prep");
	c.num.i32 = (signed int)lhs.num.i32 > (signed int)rhs.num.i32;
	return stack_pushval(interp, &c);
}

static INLINE int interp_i64_sub(struct wasm_interp *interp)
{
	struct val lhs, rhs, c;
	if (unlikely(!interp_prep_binop(interp, &lhs, &rhs, &c, val_i64)))
		return interp_error(interp, "binop prep");
	c.num.i64 = lhs.num.i64 - rhs.num.i64;
	return stack_pushval(interp, &c);
}

static INLINE int interp_i64_ge_u(struct wasm_interp *interp)
{
	struct val lhs, rhs, c;
	if (unlikely(!interp_prep_binop(interp, &lhs, &rhs, &c, val_i64)))
		return interp_error(interp, "binop prep");
	c.type = val_i32;
	c.num.i32 = lhs.num.i64 >= rhs.num.i64;
	return stack_pushval(interp, &c);
}

static INLINE int interp_i64_mul(struct wasm_interp *interp)
{
	struct val lhs, rhs, c;
	if (unlikely(!interp_prep_binop(interp, &lhs, &rhs, &c, val_i64)))
		return interp_error(interp, "binop prep");
	c.num.i64 = lhs.num.i64 * rhs.num.i64;
	return stack_pushval(interp, &c);
}

static INLINE int interp_i64_div_u(struct wasm_interp *interp)
{
	struct val lhs, rhs, c;
	if (unlikely(!interp_prep_binop(interp, &lhs, &rhs, &c, val_i64)))
		return interp_error(interp, "binop prep");
	if (rhs.num.u64 == 0)
		return interp_error(interp, "congrats, you divided by zero");
	c.num.u64 = lhs.num.u64 / rhs.num.u64;
	return stack_pushval(interp, &c);
}

static int interp_i64_eqz(struct wasm_interp *interp)
{
	struct val a, res;
	if (unlikely(!stack_pop_valtype(interp, val_i64, &a)))
		return interp_error(interp, "pop val");
	res.type = val_i32;
	res.num.i64 = a.num.i64 == 0;
	return cursor_pushval(&interp->stack, &res);
}

static INLINE int interp_i64_gt_s(struct wasm_interp *interp)
{
	struct val lhs, rhs, c;
	if (unlikely(!interp_prep_binop(interp, &lhs, &rhs, &c, val_i64)))
		return interp_error(interp, "binop prep");
	c.type = val_i32;
	c.num.i32 = lhs.num.i64 > rhs.num.i64;
	return stack_pushval(interp, &c);
}

static INLINE int interp_i64_gt_u(struct wasm_interp *interp)
{
	struct val lhs, rhs, c;
	if (unlikely(!interp_prep_binop(interp, &lhs, &rhs, &c, val_i64)))
		return interp_error(interp, "binop prep");
	c.type = val_i32;
	c.num.i32 = lhs.num.u64 > rhs.num.u64;
	return stack_pushval(interp, &c);
}

static INLINE int interp_i32_gt_u(struct wasm_interp *interp)
{
	struct val lhs, rhs, c;
	if (unlikely(!interp_prep_binop(interp, &lhs, &rhs, &c, val_i32)))
		return interp_error(interp, "binop prep");
	c.num.i32 = lhs.num.u32 > rhs.num.u32;
	return stack_pushval(interp, &c);
}

static INLINE int interp_i32_div_u(struct wasm_interp *interp)
{
	struct val lhs, rhs, c;
	if (unlikely(!interp_prep_binop(interp, &lhs, &rhs, &c, val_i32)))
		return interp_error(interp, "binop prep");
	if (rhs.num.u64 == 0)
		return interp_error(interp, "congrats, you divided by zero");
	c.num.i32 = lhs.num.i32 / rhs.num.i32;
	return stack_pushval(interp, &c);
}

static INLINE int interp_i32_ge_u(struct wasm_interp *interp)
{
	struct val lhs, rhs, c;
	if (unlikely(!interp_prep_binop(interp, &lhs, &rhs, &c, val_i32)))
		return interp_error(interp, "binop prep");
	c.num.i32 = (unsigned int)lhs.num.i32 >= (unsigned int)rhs.num.i32;
	return stack_pushval(interp, &c);
}

static INLINE int interp_i32_ge_s(struct wasm_interp *interp)
{
	struct val lhs, rhs, c;
	if (unlikely(!interp_prep_binop(interp, &lhs, &rhs, &c, val_i32)))
		return interp_error(interp, "binop prep");
	c.num.i32 = (signed int)lhs.num.i32 >= (signed int)rhs.num.i32;
	return stack_pushval(interp, &c);
}

static INLINE int interp_i32_le_s(struct wasm_interp *interp)
{
	struct val lhs, rhs, c;
	if (unlikely(!interp_prep_binop(interp, &lhs, &rhs, &c, val_i32)))
		return interp_error(interp, "binop prep");
	c.num.i32 = (signed int)lhs.num.i32 <= (signed int)rhs.num.i32;
	return stack_pushval(interp, &c);
}

static INLINE int interp_i64_const(struct wasm_interp *interp, u64 c)
{
	struct val val;
	make_i64_val(&val, c);
	return cursor_pushval(&interp->stack, &val);
}


static INLINE int interp_i32_const(struct wasm_interp *interp, u32 c)
{
	struct val val;
	make_i32_val(&val, c);
	return cursor_pushval(&interp->stack, &val);
}

static INLINE int count_local_resolvers(struct wasm_interp *interp, int *count)
{
	int offset;
	u8 *p;
	*count = 0;
	if (unlikely(!cursor_top_int(&interp->resolver_offsets, &offset))) {
		return interp_error(interp, "no top resolver offset?");
	}
	p = interp->resolver_stack.start + offset * sizeof(struct resolver);
	if (unlikely(p < interp->resolver_stack.start ||
		     p >= interp->resolver_stack.end)) {
		return interp_error(interp, "resolver offset oob?");
	}
	*count = (interp->resolver_stack.p - p) / sizeof(struct resolver);
	return 1;
}

static INLINE int drop_callframe(struct wasm_interp *interp)
{
	int count, offset;

	if (!count_local_resolvers(interp, &count)) {
		return interp_error(interp, "count local resolvers");
	}

	if (count != 0) {
		return interp_error(interp, "unclean callframe drop, still have"
				" %d unpopped labels", count);
	}

	if (!cursor_popint(&interp->resolver_offsets, &offset)) {
		return interp_error(interp, "pop resolver_offsets");
	}

	return cursor_drop_callframe(&interp->callframes);
}

static INLINE int call_wasm_func(struct wasm_interp *interp, struct wasm_func *func, int fn)
{
	struct callframe callframe;

	/* update current function and push it to the callframe as well */
	make_cursor(func->code.code, func->code.code + func->code.code_len, &callframe.code);
	callframe.fn = fn;

	assert(func->code.code_len > 0);

	if (unlikely(!cursor_push_callframe(&interp->callframes, &callframe)))
		return interp_error(interp, "oob cursor_pushcode");

	if (unlikely(!interp_code(interp))) {
		return interp_error(interp, "call %s:%d",
				get_function_name(interp->module, fn),
				fn);
	}

	if (unlikely(!drop_callframe(interp)))
		return interp_error(interp, "drop callframe");

	return 1;
}


static INLINE int call_builtin_func(struct wasm_interp *interp, struct builtin *builtin, int fn)
{
	struct callframe callframe = {};

	/* update current function and push it to the callframe as well */
	callframe.fn = fn;

	if (unlikely(!cursor_push_callframe(&interp->callframes, &callframe))) {
		return interp_error(interp, "oob cursor_pushcode");
	}

	if (!builtin->fn(interp))
		return interp_error(interp, "builtin trap");

	if (unlikely(!drop_callframe(interp)))
		return interp_error(interp, "pop callframe");

	return 1;
}

static INLINE int call_func(struct wasm_interp *interp, struct func *func, int fn)
{
	switch (func->type) {
	case func_type_wasm:
		return call_wasm_func(interp, func->wasm_func, fn);
	case func_type_builtin:
		if (func->builtin == NULL) {
			return interp_error(interp,
					"attempted to call unresolved fn: %s",
					func->name);
		}
		return call_builtin_func(interp, func->builtin, fn);
	}
	return interp_error(interp, "corrupt func type: %02x", func->type);
}

static INLINE int count_resolvers(struct wasm_interp *interp)
{
	return cursor_count(&interp->resolver_stack, sizeof(struct resolver));
}

static void make_default_val(struct val *val)
{
	switch (val->type) {
	case val_i32:
		val->num.i32 = 0;
		break;
	case val_i64:
		val->num.i64 = 0;
		break;
	case val_f32:
		val->num.f32 = 0.0;
		break;
	case val_f64:
		val->num.f64 = 0.0;
		break;
	case val_ref_null:
	case val_ref_func:
	case val_ref_extern:
		val->ref.addr = 0;
		break;
	}
}

static int prepare_function_args(struct wasm_interp *interp, struct func *func,
		int func_index)
{
	static char buf[128];
	struct local *local;
	enum valtype paramtype;
	struct val val;
	u32 i, ind;

	/* push params as locals */
	for (i = 0; i < func->functype->params.num_valtypes; i++) {
		ind = func->functype->params.num_valtypes-1-i;
		paramtype = (enum valtype)func->functype->params.valtypes[ind];
		//ind = i;
		local = &func->locals[ind];

		if (unlikely(!cursor_popval(&interp->stack, &val))) {
			return interp_error(interp,
				"not enough arguments for call to %s: [%s], needed %d args, got %d",
				get_function_name(interp->module, func_index),
				functype_str(func->functype, buf, sizeof(buf)),
				func->functype->params.num_valtypes,
				ind);
		}

		if (unlikely(val.type != paramtype)) {
			return interp_error(interp,
				"call parameter %d type mismatch. got %s, expected %s",
				ind+1,
				valtype_name(val.type),
				valtype_name(paramtype));
		}

		debug("setting param %d (%s) to ",
				ind, valtype_name(local->val.type));
#ifdef DEBUG
		print_val(&val); printf("\n");
#endif
		memcpy(&func->locals[ind], &val, sizeof(struct val));
	}


	for (i=func->functype->params.num_valtypes;
	     i < func->num_locals; i++) {
		local = &func->locals[i];
		make_default_val(&local->val);
		debug("setting local %d (%s) to default\n",
				i-func->functype->params.num_valtypes,
				valtype_name(local->val.type));
	}

	return 1;
}

static int call_function(struct wasm_interp *interp, int func_index)
{
	struct func *func;
	unsigned int offset;

	debug("calling %s:%d\n", get_function_name(interp->module, func_index), func_index);

	if (unlikely(!(func = get_function(interp->module, func_index)))) {
		return interp_error(interp,
				"function %s (%d) not found (%d funcs)",
				get_function_name(interp->module, func_index),
				func_index,
				interp->module->code_section.num_funcs);
	}

	offset = count_resolvers(interp);
	/* push label resolver offsets, used to keep track of per-func resolvers */
	/* TODO: maybe move this data to struct func? */
	if (unlikely(!cursor_push_int(&interp->resolver_offsets, offset)))
		return interp_error(interp, "push resolver offset");

	if (!prepare_function_args(interp, func, func_index)) {
		return interp_error(interp, "prepare args");
	}

	if (unlikely(!call_func(interp, func, func_index))) {
		return interp_error(interp, "call func");
	}

	return 1;
}

static int interp_call(struct wasm_interp *interp, int func_index)
{
#ifdef DEBUG
	struct callframe prev_frame;

	assert(top_callframe(&interp->callframes));
	memcpy(&prev_frame, top_callframe(&interp->callframes), sizeof(struct callframe));
#endif

	if (unlikely(!call_function(interp, func_index))) {
		return interp_error(interp, "prepare");
	}

	debug("returning from %s:%d to %s:%d\n",
			get_function_name(interp->module, func_index),
			func_index,
			get_function_name(interp->module, prev_frame.fn),
			prev_frame.fn);

	return 1;
}

static int interp_call_indirect(struct wasm_interp *interp, struct call_indirect *call)
{
	static char buf[128];
	static char buf2[128];
	struct functype *type;
	struct func *func;
	struct table_inst *table;
	struct refval *ref;
	u32 ftidx;
	int i;

	if (unlikely(!was_section_parsed(interp->module, section_table))) {
		return interp_error(interp, "no table section");
	}

	if (unlikely(call->tableidx >= interp->module_inst.num_tables)) {
		return interp_error(interp, "invalid table index %d (max %d)",
				call->tableidx,
				interp->module_inst.num_tables-1);
	}

	if (unlikely(call->typeidx >=
		     interp->module->type_section.num_functypes)) {
		return interp_error(interp, "invalid function type index: %d (max %d)",
			call->typeidx,
			interp->module->type_section.num_functypes);
	}

	table = &interp->module_inst.tables[call->tableidx];
	type = &interp->module->type_section.functypes[call->typeidx];

	if (unlikely(table->reftype != funcref)) {
		return interp_error(interp,
				"table[%d] is not a function reference table",
				call->tableidx
				);
	}

	if (unlikely(!stack_pop_i32(interp, &i))) {
		return interp_error(interp, "pop i32");
	}

	if (unlikely(i >= (int)table->num_refs)) {
		return interp_error(interp, "invalid index %d in table %d (max %d)",
				i, call->tableidx, table->num_refs-1);
	}

	ref = &table->refs[i];

	if (ref->addr == 0) {
		return interp_error(interp, "null ref in index %d of table %d",
				i, call->tableidx);
	}

	if (ref->addr >= interp->module->num_funcs) {
		return interp_error(interp, "invalid function ref %d (max %d)",
				ref, interp->module->num_funcs-1);
	}

	func = &interp->module->funcs[ref->addr];

	if (func->functype != type) {
		ftidx = (func->functype -
			 interp->module->type_section.functypes
			) / sizeof(struct functype);

		return interp_error(interp,
				"functype mismatch, expected %d `%s`, got %d `%s`",
				ftidx,
				functype_str(func->functype, buf, sizeof(buf)),
				call->typeidx,
				functype_str(type, buf2, sizeof(buf2)),
				ref, interp->module->num_funcs-1);
	}

	debug("calling %s:%d indirectly\n",
			get_function_name(interp->module, ref->addr),
			ref->addr);

	return interp_call(interp, ref->addr);
}

static int parse_blocktype(struct cursor *cur, struct errors *errs, struct blocktype *blocktype)
{
	unsigned char byte;

	if (unlikely(!pull_byte(cur, &byte))) {
		return note_error(errs, cur, "parse_blocktype: oob\n");
	}

	if (byte == 0x40) {
		blocktype->tag = blocktype_empty;
	} else if (is_valtype(byte)) {
		blocktype->tag = blocktype_valtype;
		blocktype->valtype = (enum valtype)byte;
	} else {
		blocktype->tag = blocktype_index;
		cur->p--;

		// TODO: this should be read_s64
		if (!read_int(cur, &blocktype->type_index)) {
			note_error(errs, cur, "parse_blocktype: read type_index\n");
			return 0;
		}
	}

	return 1;
}

static INLINE struct label *index_label(struct cursor *a, u32 fn, u32 ind)
{
	return index_cursor(a, ((MAX_LABELS * fn) + ind), sizeof(struct label));
}

static INLINE u32 label_instr_pos(struct label *label)
{
	return label->instr_pos & 0x7FFFFFFF;
}

static INLINE int is_label_resolved(struct label *label)
{
	return label->instr_pos & 0x80000000;
}

static struct label *index_frame_label(struct wasm_interp *interp, u32 ind)
{
	struct callframe *frame;

	frame = top_callframe(&interp->callframes);
	if (unlikely(!frame)) {
		interp_error(interp, "no callframe?");
		return NULL;
	}

	return index_label(&interp->labels, frame->fn, ind);
}

static INLINE int resolve_label(struct label *label, struct cursor *code)
{
	if (is_label_resolved(label)) {
		return 1;
	}

	label->jump = code->p - code->start;
	label->instr_pos |= 0x80000000;

	debug("resolving label %04x to %04x\n",
			label_instr_pos(label),
			label->jump);

	return 1;
}

static INLINE int pop_resolver(struct wasm_interp *interp,
		struct resolver *resolver)
{
	/*
#ifdef DEBUG
	int num_resolvers;
	struct label *label;
#endif
*/

	if (!cursor_pop(&interp->resolver_stack, (u8*)resolver, sizeof(*resolver))) {
		return interp_error(interp, "pop resolver");
	}

	/*
#ifdef DEBUG
	if (unlikely(!count_local_resolvers(interp, &num_resolvers))) {
		return interp_error(interp, "local resolvers fn start");
	};

	label = index_label(&interp->labels,
			    top_callframe(&interp->callframes)->fn,
			    resolver->label);
#endif

	debug("%04lX popped resolver %04x-%04x i_%s i_%s %d local_resolvers:%d\n",
			interp_codeptr(interp)->p - interp_codeptr(interp)->start,
			label_instr_pos(label),
			label->jump,
			instr_name(resolver->start_tag),
			instr_name(resolver->end_tag),
			count_resolvers(interp),
			num_resolvers
			);
			*/
	return 1;
}

static int pop_label(struct wasm_interp *interp,
		struct resolver *resolver,
		struct callframe **frame,
		struct label **label)
{
	if (unlikely(!pop_resolver(interp, resolver)))
		return interp_error(interp, "couldn't pop jump resolver stack");

	if (unlikely(!(*frame = top_callframe(&interp->callframes))))
		return interp_error(interp, "no callframe?");

	if (unlikely(!(*label = index_label(&interp->labels, (*frame)->fn,
					    resolver->label))))
		return interp_error(interp, "index label");

	if (unlikely(!resolve_label(*label, &(*frame)->code)))
		return interp_error(interp, "resolve label");

	return 1;
}

static INLINE int pop_label_checkpoint(struct wasm_interp *interp)
{
	struct resolver resolver;
	struct callframe *frame;
	struct label *label;

	return pop_label(interp, &resolver, &frame, &label);
}

static INLINE u16 *func_num_labels(struct wasm_interp *interp, u32 fn)
{
	u16 *num = index_cursor(&interp->num_labels, fn, sizeof(u16));
	assert(num);
	assert(*num <= MAX_LABELS);
	return num;
}

static int find_label(struct wasm_interp *interp, u32 fn, u32 instr_pos)
{
	u16 *num_labels, i;
	struct label *label;

	num_labels = func_num_labels(interp, fn);

	if (!(label = index_label(&interp->labels, fn, 0)))
		return interp_error(interp, "index label");

	for (i = 0; i < *num_labels; label++) {
		assert((u8*)label < interp->labels.end);
		if (label_instr_pos(label) == instr_pos)
			return i;
		i++;
	}

	return -1;
}

static INLINE void set_label_pos(struct label *label, u32 pos)
{
	assert(!(pos & 0x80000000));
	label->instr_pos = pos;
}

// upsert an unresolved label
static int upsert_label(struct wasm_interp *interp, u32 fn,
			u32 instr_pos, int *ind)
{
	struct label *label;
	u16 *num_labels;

	num_labels = func_num_labels(interp, fn);

	if (*num_labels > 0 && ((*ind = find_label(interp, fn, instr_pos)) != -1)) {
		// we already have the label
		return 1;
	}

	if (*num_labels + 1 > MAX_LABELS) {
		interp_error(interp, "too many labels in %s (> %d)",
			get_function_name(interp->module, fn), MAX_LABELS);
		return 0;
	}

	/*
	debug("upsert_label: %d labels for %s:%d\n",
	      *num_labels, get_function_name(interp->module, fn), fn);
	      */

	*ind = *num_labels;
	if (unlikely(!(label = index_label(&interp->labels, fn, *ind))))
		return interp_error(interp, "index label");

	set_label_pos(label, instr_pos);
	*num_labels = *num_labels + 1;

	return 2;
}

static INLINE int cursor_push_resolver(struct cursor *stack, struct resolver *resolver)
{
	return cursor_push(stack, (u8*)resolver, sizeof(*resolver));
}

struct tag_info {
	u8 flags;
	u8 end_tag;
};

// when we encounter a control instruction, try to resolve the label, otherwise
// push the label index to the resolver stack for resolution later
static int push_label_checkpoint(struct wasm_interp *interp, struct label **label,
		u8 start_tag, u8 end_tag)
{
	u32 instr_pos, fns;
	int ind;
	struct resolver resolver;
	struct callframe *frame;

	/*
#ifdef DEBUG
	int num_resolvers;
#endif
*/

	resolver.start_tag = start_tag;
	resolver.end_tag = end_tag;
	resolver.label = 0;

	*label = NULL;

	fns = interp->module->num_funcs;
	frame = top_callframe(&interp->callframes);

	if (unlikely(!frame)) {
		return interp_error(interp, "no callframes available?");
	} else if (unlikely(frame->fn >= fns)) {
		return interp_error(interp, "invalid fn index?");
	}

	instr_pos = frame->code.p - frame->code.start;
	if (unlikely(!upsert_label(interp, frame->fn, instr_pos, &ind))) {
		return interp_error(interp, "upsert label");
	}

	if (unlikely(!(*label = index_label(&interp->labels, frame->fn, ind)))) {
		return interp_error(interp, "couldn't index label");
	}

	resolver.label = ind;

	if (unlikely(!cursor_push_resolver(&interp->resolver_stack, &resolver))) {
		return interp_error(interp, "push label index to resolver stack oob");
	}

	/*
#ifdef DEBUG
	if (unlikely(!count_local_resolvers(interp, &num_resolvers))) {
		return interp_error(interp, "local resolvers fn start");
	};
#endif
	debug("pushed resolver 0x%04X-0x%04X i_%s i_%s %ld local_resolvers:%d \n",
			label_instr_pos(*label),
			(*label)->jump,
			instr_name(resolver.start_tag),
			instr_name(resolver.end_tag),
			cursor_count(&interp->resolver_stack, sizeof(resolver)),
			num_resolvers);
			*/

	return 1;
}

static int interp_jump(struct wasm_interp *interp, int jmp)
{
	struct callframe *frame;

	frame = top_callframe(&interp->callframes);
	if (unlikely(!frame)) {
		return interp_error(interp, "no callframe?");
	}

	debug("jumping to %04x\n", jmp);
	frame->code.p = frame->code.start + jmp;

	if (unlikely(frame->code.p >= frame->code.end)) {
		return interp_error(interp,
			"code pointer at or past end, evil jump?");
	}

	return 1;
}

static INLINE struct resolver *top_resolver_stack(struct cursor *stack, int index)
{
	struct resolver *p = (struct resolver*)stack->p;
	p = &p[-(index+1)];
	if (p < (struct resolver*)stack->start)
		return NULL;
	return p;
}

static INLINE struct resolver *top_resolver(struct wasm_interp *interp, u32 index)
{
	return top_resolver_stack(&interp->resolver_stack, index);
}

static int break_jump(struct wasm_interp *interp, struct resolver *resolver,
		struct label *label)
{
	/*
	debug("break jumping to %s %s\n",
			instr_name(resolver->start_tag),
			instr_name(resolver->end_tag)
			);
			*/

	if (resolver->start_tag != i_loop)
		return interp_jump(interp, label->jump);

	return interp_jump(interp, label_instr_pos(label));
}

static int pop_label_and_skip(struct wasm_interp *interp, struct label *label,
		int times)
{
	int i;
	struct resolver resolver;
	assert(is_label_resolved(label));
	
	if (unlikely(times == 0))
		return interp_error(interp, "can't pop label 0 times");

	for (i = 0; i < times; i++) {
		if (!pop_resolver(interp, &resolver)) {
			return interp_error(interp, "top resolver");
		}
	}

	return interp_jump(interp, label->jump);
}

static int pop_label_and_break(struct wasm_interp *interp, struct label *label,
		int times)
{
	int i;
	struct resolver resolver;
	assert(is_label_resolved(label));
	
	if (unlikely(times == 0))
		return interp_error(interp, "can't pop label 0 times");

	for (i = 0; i < times; i++) {
		if (!pop_resolver(interp, &resolver)) {
			return interp_error(interp, "pop resolver");
		}
	}

	// we have a loop, push the popped resolver
	if (resolver.start_tag == i_loop) {
		debug("repushing resolver\n");
		if (unlikely(!cursor_push_resolver(&interp->resolver_stack, &resolver))) {
			return interp_error(interp, "re-push loop resolver");
		}
	}

	if (!(label = index_frame_label(interp, resolver.label))) {
		return interp_error(interp, "index label");
	}
	
	return break_jump(interp, &resolver, label);
}

static int parse_block(struct expr_parser *p, struct block *block, u8 start_tag, u8 end_tag)
{
	struct label *label = NULL;

	if (!parse_blocktype(p->code, p->errs, &block->type))
		return note_error(p->errs, p->code, "blocktype");

	// if we don't have an interpreter instance, we don't care about
	// label resolution (NOT TRUE ANYMORE!)
	if (p->interp != NULL && !push_label_checkpoint(p->interp, &label, start_tag, i_end))
		return note_error(p->errs, p->code, "push checkpoint");

	if (label && is_label_resolved(label)) {
		debug("label is resolved, skipping block parse\n");
		// TODO verify this is correct
		block->instrs     = p->code->start + label_instr_pos(label);
		block->instrs_len = (p->code->start + label->jump) - block->instrs;

		return pop_label_and_skip(p->interp, label, 1);
	}

	if (!parse_instrs_until(p, end_tag, &block->instrs, &block->instrs_len))
		return note_error(p->errs, p->code, "parse instrs");

	if (p->interp)
		return pop_label_checkpoint(p->interp);

	return 1;
}

static INLINE int parse_memarg(struct cursor *code, struct memarg *memarg)
{
	return read_u32(code, &memarg->align) &&
	       read_u32(code, &memarg->offset);
}

static int parse_call_indirect(struct cursor *code,
		struct call_indirect *call_indirect)
{
	return read_u32(code, &call_indirect->typeidx) &&
	       read_u32(code, &call_indirect->tableidx);
}

static int parse_br_table(struct cursor *code, struct errors *errs,
		struct br_table *br_table)
{
	u32 i;

	if (unlikely(!read_u32(code, &br_table->num_label_indices))) {
		return note_error(errs, code, "fail read br_table num_indices");
	}

	for (i = 0; i < br_table->num_label_indices; i++) {
		if (unlikely(!read_u32(code, &br_table->label_indices[i]))) {
			return note_error(errs, code,
					  "failed to read br_table label %d/%d",
					  i+1, br_table->num_label_indices);
		}
	}

	if (unlikely(!read_u32(code, &br_table->default_label))) {
		return note_error(errs, code, "failed to parse default label");
	}

	return 1;
}

static int parse_select(struct cursor *code, struct errors *errs, u8 tag,
		struct select_instr *select)
{
	if (tag == i_select) {
		select->num_valtypes = 0;
		select->valtypes = NULL;
		return 1;
	}

	if (unlikely(!read_u32(code, &select->num_valtypes))) {
		return note_error(errs, code,
				"couldn't parse select valtype vec count");
	}

	select->valtypes = code->p;
	code->p += select->num_valtypes;

	return 1;
}

static int parse_instr(struct expr_parser *p, u8 tag, struct instr *op)
{
	op->pos = p->code->p - 1 - p->code->start;
	op->tag = tag;

	switch (tag) {
		// two-byte instrs
		case i_select:
		case i_selects:
			return parse_select(p->code, p->errs, tag, &op->select);

		case i_memory_size:
		case i_memory_grow:
			return consume_byte(p->code, 0);

		case i_block:
			return parse_block(p, &op->block, i_block, i_end);
		case i_loop:
			return parse_block(p, &op->block, i_loop, i_end);
		case i_if:
			return parse_block(p, &op->block, i_if, i_end);

		case i_else:
		case i_end:
			return 1;

		case i_call:
		case i_local_get:
		case i_local_set:
		case i_local_tee:
		case i_global_get:
		case i_global_set:
		case i_br:
		case i_br_if:
		case i_ref_func:
		case i_table_set:
		case i_table_get:
			if (!read_u32(p->code, &op->u32)) {
				return note_error(p->errs, p->code,
						"couldn't read int");
			}
			return 1;

		case i_i32_const:
			if (!read_int(p->code, &op->i32)) {
				return note_error(p->errs, p->code,
						"couldn't read int");
			}
			return 1;

		case i_i64_const:
			if (!read_i64(p->code, &op->i64)) {
				return note_error(p->errs, p->code,
						"couldn't read i64");
			}
			return 1;

		case i_i32_load:
		case i_i64_load:
		case i_f32_load:
		case i_f64_load:
		case i_i32_load8_s:
		case i_i32_load8_u:
		case i_i32_load16_s:
		case i_i32_load16_u:
		case i_i64_load8_s:
		case i_i64_load8_u:
		case i_i64_load16_s:
		case i_i64_load16_u:
		case i_i64_load32_s:
		case i_i64_load32_u:
		case i_i32_store:
		case i_i64_store:
		case i_f32_store:
		case i_f64_store:
		case i_i32_store8:
		case i_i32_store16:
		case i_i64_store8:
		case i_i64_store16:
		case i_i64_store32:
			return parse_memarg(p->code, &op->memarg);

		case i_br_table:
			return parse_br_table(p->code, p->errs, &op->br_table);

		case i_call_indirect:
			return parse_call_indirect(p->code, &op->call_indirect);

		case i_f32_const:
		case i_f64_const:
			return note_error(p->errs, p->code, "parse float const");


		// single-tag ops
		case i_unreachable:
		case i_nop:
		case i_return:
		case i_drop:
		case i_i32_eqz:
		case i_i32_eq:
		case i_i32_ne:
		case i_i32_lt_s:
		case i_i32_lt_u:
		case i_i32_gt_s:
		case i_i32_gt_u:
		case i_i32_le_s:
		case i_i32_le_u:
		case i_i32_ge_s:
		case i_i32_ge_u:
		case i_i64_eqz:
		case i_i64_eq:
		case i_i64_ne:
		case i_i64_lt_s:
		case i_i64_lt_u:
		case i_i64_gt_s:
		case i_i64_gt_u:
		case i_i64_le_s:
		case i_i64_le_u:
		case i_i64_ge_s:
		case i_i64_ge_u:
		case i_f32_eq:
		case i_f32_ne:
		case i_f32_lt:
		case i_f32_gt:
		case i_f32_le:
		case i_f32_ge:
		case i_f64_eq:
		case i_f64_ne:
		case i_f64_lt:
		case i_f64_gt:
		case i_f64_le:
		case i_f64_ge:
		case i_i32_clz:
		case i_i32_add:
		case i_i32_sub:
		case i_i32_mul:
		case i_i32_div_s:
		case i_i32_div_u:
		case i_i32_rem_s:
		case i_i32_rem_u:
		case i_i32_and:
		case i_i32_or:
		case i_i32_xor:
		case i_i32_shl:
		case i_i32_shr_s:
		case i_i32_shr_u:
		case i_i32_rotl:
		case i_i32_rotr:
		case i_i64_clz:
		case i_i64_ctz:
		case i_i64_popcnt:
		case i_i64_add:
		case i_i64_sub:
		case i_i64_mul:
		case i_i64_div_s:
		case i_i64_div_u:
		case i_i64_rem_s:
		case i_i64_rem_u:
		case i_i64_and:
		case i_i64_or:
		case i_i64_xor:
		case i_i64_shl:
		case i_i64_shr_s:
		case i_i64_shr_u:
		case i_i64_rotl:
		case i_i64_rotr:
		case i_f32_abs:
		case i_f32_neg:
		case i_f32_ceil:
		case i_f32_floor:
		case i_f32_trunc:
		case i_f32_nearest:
		case i_f32_sqrt:
		case i_f32_add:
		case i_f32_sub:
		case i_f32_mul:
		case i_f32_div:
		case i_f32_min:
		case i_f32_max:
		case i_f32_copysign:
		case i_f64_abs:
		case i_f64_neg:
		case i_f64_ceil:
		case i_f64_floor:
		case i_f64_trunc:
		case i_f64_nearest:
		case i_f64_sqrt:
		case i_f64_add:
		case i_f64_sub:
		case i_f64_mul:
		case i_f64_div:
		case i_f64_min:
		case i_f64_max:
		case i_f64_copysign:
		case i_i32_wrap_i64:
		case i_i32_trunc_f32_s:
		case i_i32_trunc_f32_u:
		case i_i32_trunc_f64_s:
		case i_i32_trunc_f64_u:
		case i_i64_extend_i32_s:
		case i_i64_extend_i32_u:
		case i_i64_trunc_f32_s:
		case i_i64_trunc_f32_u:
		case i_i64_trunc_f64_s:
		case i_i64_trunc_f64_u:
		case i_f32_convert_i32_s:
		case i_f32_convert_i32_u:
		case i_f32_convert_i64_s:
		case i_f32_convert_i64_u:
		case i_f32_demote_f64:
		case i_f64_convert_i32_s:
		case i_f64_convert_i32_u:
		case i_f64_convert_i64_s:
		case i_f64_convert_i64_u:
		case i_f64_promote_f32:
		case i_i32_reinterpret_f32:
		case i_i64_reinterpret_f64:
		case i_f32_reinterpret_i32:
		case i_f64_reinterpret_i64:
		case i_i32_extend8_s:
		case i_i32_extend16_s:
		case i_i64_extend8_s:
		case i_i64_extend16_s:
		case i_i64_extend32_s:
			return 1;
	}

	return note_error(p->errs, p->code, "unhandled tag: 0x%x", tag);
}

static int branch_jump(struct wasm_interp *interp, u8 start_tag, u8 end_tag)
{
	u8 *instrs;
	u32 instrs_len;
	struct expr_parser parser;
	struct label *label;

	if (!push_label_checkpoint(interp, &label, start_tag, end_tag)) {
		return interp_error(interp, "label checkpoint");
	}

	if (!label) {
		return interp_error(interp, "no label?");
	}

	if (is_label_resolved(label)) {
		return pop_label_and_skip(interp, label, 1);
	}

	make_interp_expr_parser(interp, &parser);

	// consume instructions, use resolver stack to resolve jumps
	if (!parse_instrs_until(&parser, end_tag, &instrs, &instrs_len)) {
		cursor_print_around(interp_codeptr(interp), 10);
		return interp_error(interp, "parse instrs start @ %s end @ %s",
				instr_name(start_tag),
				instr_name(end_tag));
	}

	return pop_label_checkpoint(interp);
}

static int interp_block(struct wasm_interp *interp)
{
	struct cursor *code;
	struct label *label;
	struct blocktype blocktype;

	if (unlikely(!(code = interp_codeptr(interp)))) {
		interp_error(interp, "empty callstack?");
		return 0;
	}

	if (unlikely(!parse_blocktype(code, &interp->errors, &blocktype))) {
		return interp_error(interp, "couldn't parse blocktype");
	}

	if (unlikely(!push_label_checkpoint(interp, &label, i_block, i_end))) {
		return interp_error(interp, "block label checkpoint");
	}

	return 1;
}

static INLINE int interp_end(struct wasm_interp *interp)
{
	return pop_label_checkpoint(interp);

	/*
	struct resolver resolver;
	struct callframe *frame;
	struct label *label;

	debug("interp end\n");

	if (!pop_label(interp, &resolver, &frame, &label)) {
		return interp_error(interp, "pop label at end inst");
	}

	if (resolver.start_tag == i_loop) {
		debug("loop jumping at end instr\n");
		return interp_jump(interp, label->jump);
	}

	return 1;
	*/
}

static int interp_if(struct wasm_interp *interp)
{
	struct val cond;
	struct blocktype blocktype;
	struct cursor *code;

	if (unlikely(!(code = interp_codeptr(interp)))) {
		return interp_error(interp, "empty callstack?");
	}

	if (unlikely(!parse_blocktype(code, &interp->errors, &blocktype))) {
		return interp_error(interp, "couldn't parse blocktype");
	}

	if (unlikely(!cursor_popval(&interp->stack, &cond))) {
		return interp_error(interp, "if pop val");
	}

	if (cond.num.i32 == 1) {
		return 1;
	}

	if (unlikely(!branch_jump(interp, i_if, i_if))) {
		return interp_error(interp, "jump");
	}

	return 1;
}

static int interp_i32_eqz(struct wasm_interp *interp)
{
	struct val a, res;

	if (unlikely(!stack_pop_valtype(interp, val_i32, &a)))
		return interp_error(interp, "if pop val");

	res.type = val_i32;
	res.num.i32 = a.num.i32 == 0;

	return cursor_pushval(&interp->stack, &res);
}

static INLINE struct label *top_label(struct wasm_interp *interp, u32 index)
{
	struct resolver *resolver;

	if (unlikely(!(resolver = top_resolver(interp, index)))) {
		interp_error(interp, "invalid resolver index %d", index);
		return NULL;
	}

	return index_frame_label(interp, resolver->label);
}

static int unresolved_break(struct wasm_interp *interp, int index)
{
	struct expr_parser parser;
	struct callframe *frame;
	u32 instrs_len;
	u8 *instrs;

	struct resolver *resolver = NULL;
	struct label *label = NULL;

#if DEBUG
	int times;
#endif

	make_interp_expr_parser(interp, &parser);

	if (unlikely(!(frame = top_callframe(&interp->callframes)))) {
		return interp_error(interp, "no top callframe?");
	}


#if DEBUG
	times = index+1;
#endif
	debug("breaking %d times from unresolved label\n", times);

	while (index-- >= 0) {
		if (unlikely(!(resolver = top_resolver(interp, 0)))) {
			return interp_error(interp, "invalid resolver index %d",
					index);
		}

		if (unlikely(!(label = index_frame_label(interp, resolver->label)))) {
			return interp_error(interp, "no label");
		}

		// TODO: breaking from functions (return)
		if (is_label_resolved(label)) {
			if (!pop_label_and_skip(interp, label, 1))
				return interp_error(interp, "pop and jump");
			else
				continue;
		}

		if (unlikely(!parse_instrs_until(&parser, resolver->end_tag,
						 &instrs, &instrs_len))) {
			return interp_error(interp, "parsing instrs");
		}

		if (unlikely(!pop_label_checkpoint(interp))) {
		    return interp_error(interp, "pop label");
		}
	}

	debug("finished breaking %d times from unresolved label (it was a %s)\n",
			times,
			instr_name(resolver->start_tag));

	assert(resolver);
	assert(label);

	if (resolver->start_tag == i_loop) {
		debug("jumping to start of loop\n");
		if (unlikely(!cursor_push_resolver(&interp->resolver_stack,
						   resolver))) {
			return interp_error(interp, "re-push loop resolver");
		}
		return interp_jump(interp, label_instr_pos(label));
	}

	return 1;
}

static int interp_br_jump(struct wasm_interp *interp, u32 index)
{
	struct label *label;

	if (unlikely(!(label = top_label(interp, index)))) {
		return interp_error(interp, "no label?");
	}

	if (is_label_resolved(label)) {
		return pop_label_and_break(interp, label, index+1);
	}

	return unresolved_break(interp, index);
}

static INLINE int interp_br(struct wasm_interp *interp, u32 ind)
{
	return interp_br_jump(interp, ind);
}

static INLINE int interp_br_table(struct wasm_interp *interp,
				  struct br_table *br_table)
{
	int i;

	if (!stack_pop_i32(interp, &i)) {
		return interp_error(interp, "pop br_table index");
	}

	if ((u32)i < br_table->num_label_indices) {
		return interp_br_jump(interp, br_table->label_indices[i]);
	}

	return interp_br_jump(interp, br_table->default_label);
}

static INLINE int interp_br_if(struct wasm_interp *interp, u32 ind)
{
	int cond = 0;

	// TODO: can this be something other than an i32?
	if (unlikely(!stack_pop_i32(interp, &cond))) {
		return interp_error(interp, "pop br_if i32");
	}

	if (cond != 0)
		return interp_br_jump(interp, ind);

	return 1;
}

static struct val *get_global_inst(struct wasm_interp *interp, u32 ind)
{
	struct global_inst *global_inst;

	if (unlikely(!was_section_parsed(interp->module, section_global))) {
		interp_error(interp,
			"can't get global %d, no global section parsed!", ind);
		return NULL;
	}

	if (unlikely(ind >= interp->module_inst.num_globals)) {
		interp_error(interp, "invalid global index %d (max %d)", ind,
			     interp->module_inst.num_globals);
		return NULL;
	}

	global_inst = &interp->module_inst.globals[ind];

	/* copy initialized global from module to global instance */
	//memcpy(&global_inst->val, &global->val, sizeof(global_inst->val));

	return &global_inst->val;
}

static int interp_global_get(struct wasm_interp *interp, u32 ind)
{
	struct globalsec *section = &interp->module->global_section;
	struct val *global;

	// TODO imported global indices?
	if (unlikely(ind >= section->num_globals)) {
		return interp_error(interp, "invalid global index %d / %d",
				ind, section->num_globals-1);
	}

	if (!(global = get_global_inst(interp, ind))) {
		return interp_error(interp, "get global");
	}

	return stack_pushval(interp, global);
}

static INLINE int has_memory_section(struct module *module)
{
	return was_section_parsed(module, section_memory) &&
		module->memory_section.num_mems > 0;
}

static INLINE int bitwidth(enum valtype vt)
{
	switch (vt) {
	case val_i32:
	case val_f32:
		return 32;

	case val_i64:
	case val_f64:
		return 64;

	/* invalid? */
	case val_ref_null:
	case val_ref_func:
	case val_ref_extern:
		return 0;
	}

	return 0;
}

struct memtarget {
	int size;
	u8 *pos;
};

static int interp_mem_offset(struct wasm_interp *interp,
		int *N, int i, enum valtype c, struct memarg *memarg,
		struct memtarget *t)
{
	int offset, bw;

	if (unlikely(!has_memory_section(interp->module))) {
		return interp_error(interp, "no memory section");
	}

	offset = i + memarg->offset;
	bw = bitwidth(c);

	if (*N == 0) {
		*N = bw;
	}

	t->size = *N/8;
	t->pos = interp->memory.start + offset;

	if (t->pos < interp->memory.start) {
		return interp_error(interp,
				"invalid memory offset %d\n", offset);
	}

	if (t->pos + t->size > interp->memory.p) {
		return interp_error(interp,
			"mem store oob pos:%d size:%d mem:%d", offset, t->size,
				interp->memory.p - interp->memory.start);
	}

	return 1;
}

static int wrap_val(struct val *val, unsigned int size) {
	switch (val->type) {
	case val_i32:
		if (size == 32)
			return 1;
		//debug("before %d size %d (mask %lx)\n", val->num.i32, size, (1UL << size)-1);
		val->num.i32 &= (1UL << size)-1;
		//debug("after %d size %d (mask %lx)\n", val->num.i32, size, (1UL << size)-1);
		break;
	case val_i64:
		if (size == 64)
			return 1;
		val->num.i64 &= (1ULL << size)-1;
		break;
	default:
		return 0;
	}
	return 1;
}

static int store_val(struct wasm_interp *interp, int i,
		struct memarg *memarg, enum valtype type, struct val *val, int N)
{
	struct memtarget target;

	if (unlikely(!interp_mem_offset(interp, &N, i, type, memarg, &target))) {
		return interp_error(interp, "memory target");
	}

	if (N != 0) {
		if (!wrap_val(val, N)) {
			return interp_error(interp,
				"implement wrap val (truncate?) for %s",
				valtype_name(val->type));
		}
	}

	debug("storing %d at %ld (%d bytes), N:%d\n", val->num.i32,
			target.pos - interp->memory.start,
			target.size, N);

	memcpy(target.pos, &val->num.i32, target.size);

	return 1;
}

static INLINE int store_simple(struct wasm_interp *interp, int offset, struct val *val)
{
	struct memarg memarg = {};
	return store_val(interp, offset, &memarg, val->type, val, 0);
}

static INLINE int store_i32(struct wasm_interp *interp, int offset, int i)
{
	struct val val;
	make_i32_val(&val, i);
	return store_simple(interp, offset, &val);
}

static int interp_load(struct wasm_interp *interp, struct memarg *memarg,
		enum valtype type, int N, int sign)
{
	struct memtarget target;
	struct val out = {0};
	int i;

	(void)sign;

	out.type = type;

	if (unlikely(!stack_pop_i32(interp, &i)))  {
		return interp_error(interp, "pop stack");
	}

	if (unlikely(!interp_mem_offset(interp, &N, i, type, memarg, &target))) {
		return interp_error(interp, "memory target");
	}

	memcpy(&out.num.i32, target.pos, target.size);
	wrap_val(&out, target.size * 8);
	debug("loading %d from %ld (copying %d bytes)\n", out.num.i32,
			target.pos - interp->memory.start, target.size);

	if (unlikely(!stack_pushval(interp, &out))) {
		return interp_error(interp,
			"push to stack after load %s", valtype_name(type));
	}

	return 1;
}

static INLINE int load_i32(struct wasm_interp *interp, int *i)
{
	struct memarg memarg = { .offset = 0, .align = 0 };
	if (!interp_load(interp, &memarg, val_i32, 0, -1)) {
		return interp_error(interp, "load");
	}
	return stack_pop_i32(interp, i);
}

static int builtin_fd_write(struct wasm_interp *interp)
{
	struct val *fd, *iovs, *iovs_len, *written;
	int iovec_data = 0;
	int str_len = 0;

	if (!(fd = get_local(interp, 0)))
		return interp_error(interp, "fd");

	if (!(iovs = get_local(interp, 1)))
		return interp_error(interp, "iovs");

	if (!(iovs_len = get_local(interp, 2)))
		return interp_error(interp, "iovs_len");

	if (!(written = get_local(interp, 3)))
		return interp_error(interp, "written");

	debug("fd_write %d %d %d %d\n",
			fd->num.i32,
			iovs->num.i32,
			iovs_len->num.i32,
			written->num.i32
			);

	if (!stack_push_i32(interp, iovs->num.i32)) {
		return interp_error(interp, "push iovec ptr");
	}

	if (!load_i32(interp, &iovec_data)) {
		return interp_error(interp, "load iovec data");
	}

	if (!stack_push_i32(interp, iovs->num.i32 + 4)) {
		return interp_error(interp, "push iovec ptr");
	}

	if (!load_i32(interp, &str_len)) {
		return interp_error(interp, "load iovec data");
	}

	debug("fd_write len %d\n", str_len);

	if (interp->memory.start + iovec_data + str_len >=
			interp->memory.p) {
		return interp_error(interp, "fd_write oob");
	}

	if (fd->num.i32 >= 10) {
		return interp_error(interp, "weird fd %d", fd->num.i32);
	}

	written->num.i32 = write(fd->num.i32,
		interp->memory.start + iovec_data,
		str_len
		);

	if (written->num.i32 != str_len) {
		return interp_error(interp, "written %d != %d",
				written->num.i32, str_len);
	}

	return stack_push_i32(interp, written->num.i32);
}

static int builtin_get_args(struct wasm_interp *interp)
{
	struct val *argv, *argv_buf;

	if (!(argv = get_local(interp, 0)))
		return interp_error(interp, "argv");

	if (!(argv_buf = get_local(interp, 1)))
		return interp_error(interp, "argv_buf");

	if (!stack_push_i32(interp, 0))
		return interp_error(interp, "push ret");

	debug("get args %d %d\n", argv->num.i32, argv_buf->num.i32);

	return 1;
}

static int builtin_get_args_sizes(struct wasm_interp *interp)
{
	struct val *argc_addr, *argv_buf_size_addr;

	if (!(argc_addr = get_local(interp, 0)))
		return interp_error(interp, "argc");

	if (!(argv_buf_size_addr = get_local(interp, 1)))
		return interp_error(interp, "argv_buf_size");

	if (!store_i32(interp, argc_addr->num.i32, 1984))
		return interp_error(interp, "store argc");

	if (!store_i32(interp, argv_buf_size_addr->num.i32, 1))
		return interp_error(interp, "store arg buf size");

	debug("get_args_sizes %d %d\n", argc_addr->num.i32,
			argv_buf_size_addr->num.i32);

	return stack_push_i32(interp, 0);
}


static int interp_store(struct wasm_interp *interp, struct memarg *memarg,
		enum valtype type, int N)
{
	struct val c;
	int i;

	if (unlikely(!stack_pop_valtype(interp, type, &c)))  {
		return interp_error(interp, "pop stack");
	}

	if (unlikely(!stack_pop_i32(interp, &i)))  {
		return interp_error(interp, "pop stack");
	}

	return store_val(interp, i, memarg, type, &c, N);
}


static INLINE int interp_global_set(struct wasm_interp *interp, int global_ind)
{
	struct val *global, setval;

	if (unlikely(!(global = get_global_inst(interp, global_ind)))) {
		return interp_error(interp, "couldn't get global %d", global_ind);
	}

	if (unlikely(!stack_popval(interp, &setval))) {
		return interp_error(interp, "couldn't pop stack value");
	}

	memcpy(global, &setval, sizeof(setval));

	return 1;
}

static INLINE int active_pages(struct wasm_interp *interp)
{
	return cursor_count(&interp->memory, WASM_PAGE_SIZE);
}

static int interp_memory_grow(struct wasm_interp *interp, u8 memidx)
{
	int pages = 0, prev_size, grow;

	(void)memidx;

	if (unlikely(!has_memory_section(interp->module))) {
		return interp_error(interp, "no memory section");
	}

	if (!stack_pop_i32(interp, &pages)) {
		return interp_error(interp, "pop pages");
	}

	grow = pages * WASM_PAGE_SIZE;
	prev_size = active_pages(interp);

	if (interp->memory.p + grow <= interp->memory.end) {
		interp->memory.p += grow;
		pages = prev_size;
	} else {
		pages = -1;
	}

	return stack_push_i32(interp, pages);
}

static INLINE int interp_memory_size(struct wasm_interp *interp, u8 memidx)
{
	(void)memidx;

	if (unlikely(!has_memory_section(interp->module))) {
		return interp_error(interp, "no memory section");
	}

	if (!stack_push_i32(interp, active_pages(interp))) {
		return interp_error(interp, "push memory size");
	}

	return 1;
}

static INLINE int interp_i32_eq(struct wasm_interp *interp)
{
	struct val lhs, rhs, c;

	if (unlikely(!interp_prep_binop(interp, &lhs, &rhs, &c, val_i32))) {
		return interp_error(interp, "binop prep");
	}

	return stack_push_i32(interp, lhs.num.i32 == rhs.num.i32);
}

static INLINE int interp_i32_wrap_i64(struct wasm_interp *interp)
{
	int64_t n;
	if (unlikely(!stack_pop_i64(interp, &n)))
		return interp_error(interp, "pop");
	return stack_push_i32(interp, (int)n);
}

static INLINE int interp_i32_xor(struct wasm_interp *interp)
{
	struct val lhs, rhs, c;

	if (unlikely(!interp_prep_binop(interp, &lhs, &rhs, &c, val_i32))) {
		return interp_error(interp, "binop prep");
	}

	return stack_push_i32(interp, lhs.num.i32 ^ rhs.num.i32);
}

static INLINE int interp_i32_ne(struct wasm_interp *interp)
{
	struct val lhs, rhs, c;

	if (unlikely(!interp_prep_binop(interp, &lhs, &rhs, &c, val_i32))) {
		return interp_error(interp, "binop prep");
	}

	return stack_push_i32(interp, lhs.num.i32 != rhs.num.i32);
}

static INLINE int interp_i32_mul(struct wasm_interp *interp)
{
	struct val lhs, rhs, c;

	if (unlikely(!interp_prep_binop(interp, &lhs, &rhs, &c, val_i32))) {
		return interp_error(interp, "binop prep");
	}

	c.num.i32 = lhs.num.i32 * rhs.num.i32;

	return stack_pushval(interp, &c);
}

static INLINE int interp_i32_or(struct wasm_interp *interp)
{
	struct val lhs, rhs, c;

	if (unlikely(!interp_prep_binop(interp, &lhs, &rhs, &c, val_i32))) {
		return interp_error(interp, "binop prep");
	}

	c.num.i32 = lhs.num.i32 | rhs.num.i32;

	return stack_pushval(interp, &c);
}

static INLINE int interp_i32_and(struct wasm_interp *interp)
{
	struct val lhs, rhs, c;

	if (unlikely(!interp_prep_binop(interp, &lhs, &rhs, &c, val_i32))) {
		return interp_error(interp, "binop prep");
	}

	c.num.i32 = lhs.num.i32 & rhs.num.i32;

	return stack_pushval(interp, &c);
}

static int interp_i64_or(struct wasm_interp *interp)
{
	struct val lhs, rhs, c;

	if (unlikely(!interp_prep_binop(interp, &lhs, &rhs, &c, val_i64))) {
		return interp_error(interp, "binop prep");
	}

	c.num.i64 = lhs.num.i64 | rhs.num.i64;
	return stack_pushval(interp, &c);
}

static int interp_i64_shl(struct wasm_interp *interp)
{
	struct val lhs, rhs, c;

	if (unlikely(!interp_prep_binop(interp, &lhs, &rhs, &c, val_i64))) {
		return interp_error(interp, "binop prep");
	}

	c.num.i64 = lhs.num.i64 << rhs.num.i64;
	return stack_pushval(interp, &c);
}

static int interp_i32_shl(struct wasm_interp *interp)
{
	struct val lhs, rhs, c;

	if (unlikely(!interp_prep_binop(interp, &lhs, &rhs, &c, val_i32))) {
		return interp_error(interp, "binop prep");
	}

	c.num.i32 = lhs.num.i32 << rhs.num.i32;
	return stack_pushval(interp, &c);
}

#ifdef DEBUG
static void print_linestack(struct cursor *stack)
{
	struct val *val;
	int first = 1;

	val = (struct val*)stack->p;

	while (--val >= (struct val*)stack->start) {
		if (first) {
			first = 0;
		} else {
			printf(", ");
		}
		print_val(val);
	}

	printf("\n");
}

#endif

static int interp_extend(struct wasm_interp *interp, enum valtype to,
		enum valtype from, int sign)
{
	struct val *val;
	int64_t i64;
	int i32;
	(void)sign;

	if (unlikely(!(val = stack_topval(interp)))) {
		return interp_error(interp, "no value on stack");
	}

	if (val->type != from) {
		return interp_error(interp,
				"value on stack is of type %s, expected %s",
				valtype_name(val->type), valtype_name(from));
	}

	switch (from) {
	case val_i32:
		i64 = val->num.i32;
		val->num.i64 = i64;
		break;
	case val_i64:
		i32 = val->num.i64;
		val->num.i32 = i32;
		break;
	default:
		return interp_error(interp, "unhandled extend from %s to %s",
				valtype_name(from), valtype_name(to));
	}

	val->type = to;
	return 1;
}

static INLINE int interp_drop(struct wasm_interp *interp)
{
	return cursor_drop(&interp->stack, sizeof(struct val));
}

static int interp_loop(struct wasm_interp *interp)
{
	struct blocktype blocktype;
	struct cursor *code;
	struct label *label;

	if (unlikely(!(code = interp_codeptr(interp)))) {
		return interp_error(interp, "empty callstack?");
	}

	if (unlikely(!parse_blocktype(code, &interp->errors, &blocktype))) {
		return interp_error(interp, "couldn't parse blocktype");
	}

	if (unlikely(!push_label_checkpoint(interp, &label, i_loop, i_end))) {
		return interp_error(interp, "block label checkpoint");
	}

	return 1;
}

static INLINE int table_set(struct wasm_interp *interp,
		struct table_inst *table, u32 ind, struct val *val)
{

	if (unlikely(ind >= table->num_refs)) {
		return interp_error(interp, "invalid index %d (max %d)",
				ind,
				interp->module_inst.num_tables);
	}

	if (unlikely(table->reftype != (enum reftype)val->type)) {
		return interp_error(interp, "can't store %s ref in %s table",
				valtype_name(val->type),
				valtype_name((enum valtype)table->reftype));
	}

	debug("setting table[%ld] ref %d to ",
	      (table - interp->module_inst.tables) / sizeof (struct table_inst),
	      ind);
#ifdef DEBUG
	print_refval(&val->ref, table->reftype);
	printf("\n");
#endif

	memcpy(&table->refs[ind], &val->ref, sizeof(struct refval));

	return 1;
}

static int interp_table_set(struct wasm_interp *interp, u32 tableidx)
{
	struct table_inst *table;
	struct val val;
	int ind;

	if (unlikely(tableidx >= interp->module_inst.num_tables)) {
		return interp_error(interp, "tableidx oob %d (max %d)",
				tableidx,
				interp->module_inst.num_tables + 1);
	}

	table = &interp->module_inst.tables[tableidx];

	if (unlikely(!stack_pop_ref(interp, &val))) {
		return interp_error(interp, "pop ref");
	}

	if (unlikely(!stack_pop_i32(interp, &ind))) {
		return interp_error(interp, "pop elem index");
	}

	return table_set(interp, table, ind, &val);
}

static int interp_memory_init(struct wasm_interp *interp, u32 dataidx)
{
	struct wdata *data;
	int count, src, dst;
	u32 num_data;

	num_data = interp->module->data_section.num_datas;
	if (unlikely(dataidx >= num_data)) {
		return interp_error(interp, "invalid data index %d / %d",
				dataidx, num_data-1);
	}

	data = &interp->module->data_section.datas[dataidx];

	if(unlikely(!stack_pop_i32(interp, &count)))
		return interp_error(interp, "pop count");

	if(unlikely(!stack_pop_i32(interp, &src)))
		return interp_error(interp, "pop src");

	if(unlikely(!stack_pop_i32(interp, &dst)))
		return interp_error(interp, "pop dst");

	if (src + count > (int)data->bytes_len) {
		return interp_error(interp, "count %d > data len %d", count,
				data->bytes_len);
	}

	if (interp->memory.start + dst + count >= interp->memory.p) {
		return interp_error(interp, "memory write oob %d > %d",
				count, interp->memory.p - interp->memory.start);
	}

	debug("memory_init src:%d dst:%d count:%d\n",
			src, dst, count);

	memcpy(interp->memory.start + dst,
	       data->bytes + src,
	       count);

	return 1;

	/*
	for (; count; count--; dst++, src++) {
		if (unlikely(src + count > data)) {
			return interp_error(interp,
				"src %d (max %d)",
				src + count, num_data + 1);
		}

		if (unlikely(dst + count > active_pages(interp))) {
			return interp_error(interp, "dst oob",
					dst + count,
					table->num_refs + 1);
		}
	}
	*/
	return 1;
}

static int interp_table_init(struct wasm_interp *interp,
				  struct table_init *t)
{
	struct table_inst *table;
	struct elem_inst *elem_inst;
	int num_inits, dst, src;

	if (unlikely(t->tableidx >= interp->module_inst.num_tables)) {
		return interp_error(interp, "tableidx oob %d (max %d)",
				t->tableidx,
				interp->module_inst.num_tables + 1);
	}

	table = &interp->module_inst.tables[t->tableidx];

	// TODO: elem addr ?
	if (unlikely(t->elemidx >= interp->module->element_section.num_elements)) {
		return interp_error(interp, "elemidx oob %d (max %d)",
				t->elemidx,
				interp->module->element_section.num_elements + 1);
	}

	if (unlikely(!stack_pop_i32(interp, &num_inits))) {
		return interp_error(interp, "pop num_inits");
	}

	if (unlikely(!stack_pop_i32(interp, &src))) {
		return interp_error(interp, "pop src");
	}

	if (unlikely(!stack_pop_i32(interp, &dst))) {
		return interp_error(interp, "pop dst");
	}

	for (; num_inits; num_inits--, dst++, src++) {
		if (unlikely((u32)src + num_inits > interp->module_inst.num_elements)) {
			return interp_error(interp, "index oob elem.elem s+n %d (max %d)",
					src + num_inits,
					interp->module_inst.num_elements + 1);
		}

		if (unlikely((u32)dst + num_inits > table->num_refs)) {
			return interp_error(interp, "index oob tab.elem d+n %d (max %d)",
					dst + num_inits,
					table->num_refs + 1);
		}

		elem_inst = &interp->module_inst.elements[src];

		if (!table_set(interp, table, dst, &elem_inst->val)) {
			return interp_error(interp,
					"table set failed for table %d ind %d");
		}
	}

	return 1;
}

static int interp_select(struct wasm_interp *interp, struct select_instr *select)
{
	struct val top, bottom;
	int c;

	(void)select;

	if (unlikely(!stack_pop_i32(interp, &c)))
		return interp_error(interp, "pop select");

	if (unlikely(!stack_popval(interp, &top)))
		return interp_error(interp, "pop val top");

	if (unlikely(!stack_popval(interp, &bottom)))
		return interp_error(interp, "pop val bottom");

	if (unlikely(top.type != bottom.type))
		return interp_error(interp, "type mismatch, %s != %s",
				valtype_name(top.type),
				valtype_name(bottom.type));

	if (c != 0)
		return stack_pushval(interp, &bottom);
	else
		return stack_pushval(interp, &top);
}

static int interp_return(struct wasm_interp *interp)
{
	int count;

	if (unlikely(!count_local_resolvers(interp, &count))) {
		return interp_error(interp, "failed to count fn labels?");
	}

	if (unlikely(!cursor_dropn(&interp->resolver_stack,
					sizeof(struct resolver), count))) {
		return interp_error(interp, "failed to drop %d local labels",
				count);
	}

	return i_return;
}

static int interp_instr(struct wasm_interp *interp, struct instr *instr)
{
	interp->ops++;

	debug("%04X %-30s | ", instr->pos, show_instr(instr));

#if DEBUG
	print_linestack(&interp->stack);
#endif

	switch (instr->tag) {
	case i_unreachable: return interp_error(interp, "unreachable");
	case i_nop:         return 1;
	case i_select:
	case i_selects:
		return interp_select(interp, &instr->select);

	case i_local_get:   return interp_local_get(interp, instr->i32);
	case i_local_set:   return interp_local_set(interp, instr->i32);
	case i_local_tee:   return interp_local_tee(interp, instr->i32);
	case i_global_get:  return interp_global_get(interp, instr->i32);
	case i_global_set:  return interp_global_set(interp, instr->i32);

	case i_i32_eqz:     return interp_i32_eqz(interp);
	case i_i32_add:     return interp_i32_add(interp);
	case i_i32_sub:     return interp_i32_sub(interp);
	case i_i32_const:   return interp_i32_const(interp, instr->i32);
	case i_i32_div_u:   return interp_i32_div_u(interp);
	case i_i32_ge_u:    return interp_i32_ge_u(interp);
	case i_i32_ge_s:    return interp_i32_ge_s(interp);
	case i_i32_gt_u:    return interp_i32_gt_u(interp);
	case i_i32_gt_s:    return interp_i32_gt_s(interp);
	case i_i32_le_s:    return interp_i32_le_s(interp);
	case i_i32_le_u:    return interp_i32_le_u(interp);
	case i_i32_lt_s:    return interp_i32_lt_s(interp);
	case i_i32_lt_u:    return interp_i32_lt_u(interp);
	case i_i32_shl:     return interp_i32_shl(interp);
	case i_i32_or:      return interp_i32_or(interp);
	case i_i32_and:     return interp_i32_and(interp);
	case i_i32_mul:     return interp_i32_mul(interp);
	case i_i32_xor:     return interp_i32_xor(interp);
	case i_i32_ne:      return interp_i32_ne(interp);
	case i_i32_eq:      return interp_i32_eq(interp);
	case i_i32_wrap_i64:return interp_i32_wrap_i64(interp);

	case i_i64_eqz:     return interp_i64_eqz(interp);
	case i_i64_gt_s:    return interp_i64_gt_s(interp);
	case i_i64_gt_u:    return interp_i64_gt_u(interp);
	case i_i64_ge_u:    return interp_i64_ge_u(interp);
	case i_i64_div_u:   return interp_i64_div_u(interp);
	case i_i64_mul:     return interp_i64_mul(interp);
	case i_i64_shl:     return interp_i64_shl(interp);
	case i_i64_or:      return interp_i64_or(interp);
	case i_i64_sub:     return interp_i64_sub(interp);

	case i_i64_const:   return interp_i64_const(interp, instr->i64);
	case i_i64_extend_i32_u: return interp_extend(interp, val_i64, val_i32, 0);
	case i_i64_extend_i32_s: return interp_extend(interp, val_i64, val_i32, 1);

	case i_i32_store:   return interp_store(interp, &instr->memarg, val_i32, 0);
	case i_i32_store8:  return interp_store(interp, &instr->memarg, val_i32, 8);
	case i_i32_store16: return interp_store(interp, &instr->memarg, val_i32, 16);
	case i_f32_store:   return interp_store(interp, &instr->memarg, val_f32, 0);
	case i_f64_store:   return interp_store(interp, &instr->memarg, val_f64, 0);
	case i_i64_store:   return interp_store(interp, &instr->memarg, val_i64, 0);
	case i_i64_store8:  return interp_store(interp, &instr->memarg, val_i64, 8);
	case i_i64_store16: return interp_store(interp, &instr->memarg, val_i64, 16);
	case i_i64_store32: return interp_store(interp, &instr->memarg, val_i64, 32);

	case i_i32_load:     return interp_load(interp, &instr->memarg, val_i32, 0, -1);
	case i_i32_load8_s:  return interp_load(interp, &instr->memarg, val_i32, 8, 1);
	case i_i32_load8_u:  return interp_load(interp, &instr->memarg, val_i32, 8, 0);
	case i_i32_load16_s: return interp_load(interp, &instr->memarg, val_i32, 16, 1);
	case i_i32_load16_u: return interp_load(interp, &instr->memarg, val_i32, 16, 0);
	case i_f32_load:     return interp_load(interp, &instr->memarg, val_f32, 0, -1);
	case i_f64_load:     return interp_load(interp, &instr->memarg, val_f64, 0, -1);
	case i_i64_load:     return interp_load(interp, &instr->memarg, val_i64, 0, -1);
	case i_i64_load8_s:  return interp_load(interp, &instr->memarg, val_i64, 8, 1);
	case i_i64_load8_u:  return interp_load(interp, &instr->memarg, val_i64, 8, 0);
	case i_i64_load16_s: return interp_load(interp, &instr->memarg, val_i64, 16, 1);
	case i_i64_load16_u: return interp_load(interp, &instr->memarg, val_i64, 16, 0);
	case i_i64_load32_s: return interp_load(interp, &instr->memarg, val_i64, 32, 1);
	case i_i64_load32_u: return interp_load(interp, &instr->memarg, val_i64, 32, 0);

	case i_drop: return interp_drop(interp);
	case i_loop: return interp_loop(interp);
	case i_if: return interp_if(interp);
	case i_end: return interp_end(interp);
	case i_call: return interp_call(interp, instr->i32);
	case i_call_indirect: return interp_call_indirect(interp, &instr->call_indirect);
	case i_block: return interp_block(interp);
	case i_br: return interp_br(interp, instr->i32);
	case i_br_table: return interp_br_table(interp, &instr->br_table);
	case i_br_if: return interp_br_if(interp, instr->i32);
	case i_memory_size: return interp_memory_size(interp, instr->memidx);
	case i_memory_grow: return interp_memory_grow(interp, instr->memidx);
	case i_table_op: return interp_error(interp, "todo: interp table_op");
	case i_table_set: return interp_table_set(interp, instr->i32);
	case i_return: return interp_return(interp);
	default:
		    interp_error(interp, "unhandled instruction %s 0x%x",
				 instr_name(instr->tag), instr->tag);
		    return 0;
	}

	return 0;
}

static int is_control_instr(u8 tag)
{
	switch (tag) {
		case i_if:
		case i_block:
		case i_loop:
		case i_else:
			return 1;
	}
	return 0;
}


static INLINE int interp_parse_instr(struct wasm_interp *interp,
		struct cursor *code, struct expr_parser *parser,
		struct instr *instr)
{
	u8 tag;

	if (unlikely(!pull_byte(code, &tag))) {
		return interp_error(interp, "no more instrs to pull");
	}

	instr->tag = tag;
	instr->pos = code->p - 1 - code->start;

	if (is_control_instr(tag)) {
		return 1;
	}

	if (!parse_instr(parser, instr->tag, instr)) {
		return interp_error(interp, "parse instr %s", instr_name(tag));
	}

	return 1;
}

enum interp_end {
	interp_end_err,
	interp_end_done,
	interp_end_cont,
	interp_end_next,
};

// tricky...
static enum interp_end interp_code_end(struct wasm_interp *interp,
		struct callframe *frame, struct cursor *code)
{
	struct resolver *resolver;
	//struct label *label;
	int num_resolvers = 0;
	(void)frame;
	(void)code;

	if (unlikely(!(resolver = top_resolver(interp, 0)))) {
		// no more resolvers, we done.
		return interp_end_done;
	}

	if (unlikely(!count_local_resolvers(interp, &num_resolvers))) {
		return interp_error(interp, "count local resolvers");
	}

	//debug("interp_code_end local resolvers: %d\n", num_resolvers);

	if (num_resolvers == 0) {
		return interp_end_done;
	}

	// if we hit the end of a loop, continue at the start
	/*
	if (resolver && resolver->start_tag == i_loop) {
		if (unlikely(!(label = index_label(&interp->labels, frame->fn,
						   resolver->label)))) {
			return interp_error(interp, "no loop label?");
		}

		resolve_label(label, code);

		debug("loop jumping\n");
		if (!interp_jump(interp, label_instr_pos(label))) {
			return interp_error(interp, "jump to loop label");
		}

		return interp_end_cont;
	}
	*/

	return interp_end_next;
}

static int interp_elem_drop(struct wasm_interp *interp, int elemidx)
{
	(void)interp;
	(void)elemidx;
	// we don't really need to do anything here...
	return 1;
}

static int interp_code(struct wasm_interp *interp)
{
	struct instr instr;
	struct expr_parser parser;
	struct cursor *code;
	struct callframe *frame;
	int ret;

	make_interp_expr_parser(interp, &parser);

	if (unlikely(!(frame = top_callframe(&interp->callframes)))) {
		return interp_error(interp, "no callframe");
	}

	for (;;) {
		if (unlikely(!(code = interp_codeptr(interp)))) {
			return interp_error(interp, "codeptr");
		}

		if (unlikely(!interp_parse_instr(interp, code, &parser, &instr))) {
			cursor_print_around(code, 5);
			debug("end ? %d\n", top_callframe(&interp->callframes)->fn);
			return interp_error(interp, "parse instr");
		}

		if (instr.tag == i_end) {
			switch (interp_code_end(interp, frame, code)) {
				case interp_end_err: return 0;
				case interp_end_done: return 1;
				case interp_end_cont: continue;
				case interp_end_next: break;
			}
		}

		if (unlikely(!(ret = interp_instr(interp, &instr)))) {
			return interp_error(interp, "interp instr %s",
					show_instr(&instr));
		}

		if (ret == i_return)
			return 1;
	}

	return 1;
}

static int find_function(struct module *module, const char *name)
{
	struct wexport *export;
	u32 i;

	for (i = 0; i < module->export_section.num_exports; i++) {
		export = &module->export_section.exports[i];
		if (!strcmp(name, export->name)) {
			return export->index;
		}
	}

	return -1;
}

static int find_start_function(struct module *module)
{
	int res;

	if (was_section_parsed(module, section_start)) {
		debug("getting start function from start section\n");
		return module->start_section.start_fn;
	}

	if ((res = find_function(module, "start")) != -1) {
		return res;
	}

	return find_function(module, "_start");
}

void wasm_parser_init(struct wasm_parser *p, u8 *wasm, size_t wasm_len, size_t arena_size)
{
	u8 *mem;

	mem = calloc(1, arena_size);
	assert(mem);

	make_cursor(wasm, wasm + wasm_len, &p->cur);
	make_cursor(mem, mem + arena_size, &p->mem);

	p->errs.enabled = 1;

	cursor_slice(&p->mem, &p->errs.cur, 0xFFFF);
}

static int count_fn_locals(struct func *func)
{
	u32 i, num_locals = 0;

	num_locals += func->functype->params.num_valtypes;

	if (func->type == func_type_wasm) {
		// counts locals of the same type
		for (i = 0; i < func->wasm_func->num_locals; i++) {
			num_locals += func->wasm_func->locals->val.num.i32;
		}
	}

	return num_locals;
}

static int calculate_tables_size(struct module *module)
{
	u32 i, num_tables, size;
	struct table *tables;

	if (!was_section_parsed(module, section_table))
		return 0;

	tables = module->table_section.tables;
	num_tables = module->table_section.num_tables;
	size = num_tables * sizeof(struct table_inst);

	for (i = 0; i < num_tables; i++) {
		size += sizeof(struct refval) * tables[i].limits.min;
	}

	return size;
}

static int alloc_tables(struct wasm_interp *interp)
{
	struct table *t;
	struct table_inst *inst;
	u32 i, size;

	if (!was_section_parsed(interp->module, section_table))
		return 1;

	interp->module_inst.num_tables =
		interp->module->table_section.num_tables;

	if (!(interp->module_inst.tables =
		cursor_alloc(&interp->mem, interp->module_inst.num_tables *
			     sizeof(struct table_inst)))) {
		return interp_error(interp, "couldn't alloc table instances");
	}

	for (i = 0; i < interp->module_inst.num_tables; i++) {
		t = &interp->module->table_section.tables[i];
		inst = &interp->module_inst.tables[i];
		inst->reftype = t->reftype;
		inst->num_refs = t->limits.min;
		size = sizeof(struct refval) * t->limits.min;

		if (!(inst->refs = cursor_alloc(&interp->mem, size))) {
			return interp_error(interp,
				"couldn't alloc table inst %d/%d",
				i+1, interp->module->table_section.num_tables);
		}
	}

	return 1;
}


static int calculate_locals_size(struct module *module)
{
	u32 i, locals_size = 0;
	struct func *func;

	for (i = 0; i < module->num_funcs; i++) {
		func = &module->funcs[i];
		locals_size += count_fn_locals(func) * sizeof(struct val);
	}

	debug("locals size %d\n", locals_size);

	return locals_size;
}

static int alloc_locals(struct module *module, struct cursor *mem,
		struct errors *errs)
{
	u32 i, j, k, num_locals, size, sizes = 0, ind;
	struct func *func;

	for (i = 0; i < module->num_funcs; i++) {
		func = &module->funcs[i];
		num_locals = count_fn_locals(func);

		func->locals = (struct local*)mem->p;
		func->num_locals = num_locals;

		size = num_locals * sizeof(struct val);
		sizes += size;

		if (!cursor_alloc(mem, size)) {
			debug("alloc_locals err sizes %d\n", sizes);
			return note_error(errs, mem,
					"could not alloc locals for %s",
					func->name);
		}

		for (j = 0, ind = 0; j < func->functype->params.num_valtypes; j++, ind++) {
			func->locals[j].val.type = func->functype->params.valtypes[j];
		}

		if (func->type != func_type_wasm)
			continue;

		for (j = 0; j < func->wasm_func->num_locals; j++) {
		for (k = 0; k < func->wasm_func->locals[j].val.num.u32; k++, ind++) {
			debug("initializing function %d local %d to type %s\n",
				i, ind, valtype_name(
					  func->wasm_func->locals[j].val.type));

			func->locals[ind].val.type =
				func->wasm_func->locals[j].val.type;
		}
		}
	}

	debug("alloc_locals sizes %d\n", sizes);

	return 1;
}

static int init_element(struct wasm_interp *interp, struct expr *init,
		struct elem_inst *elem_inst)
{
	if (!eval_const_val(init, &interp->errors, &interp->stack, &elem_inst->val)) {
		return interp_error(interp, "failed to eval element init expr");
	}
	return 1;
}

static int init_table(struct wasm_interp *interp, struct elem *elem,
		int elemidx, int num_elems)
{
	struct table_init t;

	if (elem->tableidx != 0) {
		return interp_error(interp,
			"tableidx should be 0 for elem %d", elemidx);
	}

	if (!eval_const_expr(&elem->offset, &interp->errors, &interp->stack)) {
		return interp_error(interp, "failed to eval elem offset expr");
	}

	if (!stack_push_i32(interp, 0)) {
		return interp_error(interp, "push 0 when init element");
	}

	if (!stack_push_i32(interp, num_elems)) {
		return interp_error(interp, "push num_elems in init element");
	}

	t.tableidx = elem->tableidx;
	t.elemidx  = elemidx;

	if (!interp_table_init(interp, &t)) {
		return interp_error(interp, "table init");
	}

	if (!interp_elem_drop(interp, elemidx)) {
		return interp_error(interp, "drop elem");
	}

	return 1;
}

static int init_global(struct wasm_interp *interp, struct global *global,
		struct global_inst *global_inst)
{
	if (!eval_const_val(&global->init, &interp->errors, &interp->stack,
			    &global_inst->val)) {
		return interp_error(interp, "eval const expr");
	}

	debug("init global to %s %d\n", valtype_name(global_inst->val.type),
			global_inst->val.num.i32);

	if (cursor_top(&interp->stack, sizeof(struct val))) {
		return interp_error(interp, "stack not empty");
	}

	return 1;
}

static int init_globals(struct wasm_interp *interp)
{
	struct global *globals, *global;
	struct global_inst *global_insts, *global_inst;
	u32 i;

	if (!was_section_parsed(interp->module, section_global)) {
		// nothing to init
		return 1;
	}

	globals = interp->module->global_section.globals;
	global_insts = interp->module_inst.globals;

	for (i = 0; i < interp->module->global_section.num_globals; i++) {
		global = &globals[i];
		global_inst = &global_insts[i];

		if (!init_global(interp, global, global_inst)) {
			return interp_error(interp, "global init");
		}
	}

	return 1;
}

static int count_element_insts(struct module *module)
{
	struct elem *elem;
	u32 i, size = 0;

	if (!was_section_parsed(module, section_element))
		return 0;

	for (i = 0; i < module->element_section.num_elements; i++) {
		elem = &module->element_section.elements[i];
		size += elem->num_inits;
	}

	return size;
}

static int init_memory(struct wasm_interp *interp, struct wdata *data, int dataidx)
{
	if (!eval_const_expr(&data->active.offset_expr, &interp->errors,
				&interp->stack)) {
		return interp_error(interp, "failed to eval data offset expr");
	}

	if (!stack_push_i32(interp, 0)) {
		return interp_error(interp, "push 0 when init element");
	}

	if (!stack_push_i32(interp, data->bytes_len)) {
		return interp_error(interp, "push num_elems in init element");
	}

	if (!interp_memory_init(interp, dataidx)) {
		return interp_error(interp, "table init");
	}

	/*
	if (!interp_data_drop(interp, elemidx)) {
		return interp_error(interp, "drop elem");
	}
	*/

	return 1;
}

static int init_memories(struct wasm_interp *interp)
{
	struct wdata *data;
	int i;

	debug("init memories\n");

	if (!was_section_parsed(interp->module, section_data))
		return 1;

	if (!was_section_parsed(interp->module, section_memory))
		return 1;

	for (i = 0; i < interp->module->data_section.num_datas; i++) {
		data = &interp->module->data_section.datas[i];

		if (data->mode != datamode_active)
			continue;

		if (!init_memory(interp, data, i)) {
			return interp_error(interp, "init memory %d failed", i);
		}
	}

	return 1;
}

static int init_tables(struct wasm_interp *interp)
{
	struct elem *elem;
	u32 i;

	if (!was_section_parsed(interp->module, section_table))
		return 1;

	for (i = 0; i < interp->module->element_section.num_elements; i++) {
		elem = &interp->module->element_section.elements[i];

		if (elem->mode != elem_mode_active)
			continue;

		if (!init_table(interp, elem, i, elem->num_inits)) {
			return interp_error(interp, "init table failed");
		}
	}

	return 1;
}

static int init_elements(struct wasm_interp *interp)
{
	struct elem *elems, *elem;
	struct elem_inst *inst;
	struct expr *init;
	u32 count = 0;
	u32 i, j;

	debug("init elements\n");

	if (!was_section_parsed(interp->module, section_element))
		return 1;

	elems = interp->module->element_section.elements;

	for (i = 0; i < interp->module->element_section.num_elements; i++) {
		elem = &elems[i];

		if (elem->mode != elem_mode_active)
			continue;

		for (j = 0; j < elem->num_inits; j++, count++) {
			init = &elem->inits[j];

			assert(count < interp->module_inst.num_elements);
			inst = &interp->module_inst.elements[count];
			inst->elem = i;
			inst->init = j;

			if (!init_element(interp, init, inst)) {
				return interp_error(interp, "init element %d", j);
			}
		}

	}

	return 1;
}

// https://webassembly.github.io/spec/core/exec/modules.html#instantiation
static int instantiate_module(struct wasm_interp *interp)
{
	int func;
	//TODO:Assert module is valid with external types classifying its imports

	// TODO: If the number # of imports is not equal to the number of provided external values then fail

	/*
	if (!push_aux_callframe(interp)) {
		return interp_error(interp,
			"failed to pushed aux callframe?? "
			"ok if this happens seriously wtf why am I even"
			" writing this error message..)";
	}
	*/

	func = interp->module_inst.start_fn != -1
	     ? interp->module_inst.start_fn
	     : find_start_function(interp->module);

	memset(interp->module_inst.globals, 0,
			interp->module_inst.num_globals *
			sizeof(*interp->module_inst.globals));

	memset(interp->module_inst.globals_init, 0,
			interp->module_inst.num_globals);

	if (func == -1) {
		return interp_error(interp, "no start function found");
	} else {
		interp->module_inst.start_fn = func;
		debug("found start function %s (%d)\n",
				get_function_name(interp->module, func), func);
	}

	if (!init_memories(interp)) {
		return interp_error(interp, "memory init");
	}

	if (!init_elements(interp)) {
		return interp_error(interp, "elements init");
	}

	if (!init_tables(interp)) {
		return interp_error(interp, "table init");
	}

	if (!init_globals(interp)) {
		return interp_error(interp, "globals init");
	}

	return 1;
}

static int reset_memory(struct wasm_interp *interp)
{
	int pages, num_mems;

	num_mems = was_section_parsed(interp->module, section_memory)?
		interp->module->memory_section.num_mems : 0;

	reset_cursor(&interp->memory);

	if (num_mems == 1) {
		pages = interp->module->memory_section.mems[0].min;
		if (!cursor_malloc(&interp->memory, pages * WASM_PAGE_SIZE)) {
			return interp_error(interp,
					"could not alloc %d memory pages",
					pages);
		}
		assert(interp->memory.p > interp->memory.start);
		memset(interp->memory.start, 0, pages * WASM_PAGE_SIZE);
	}

	return 1;
}

int wasm_interp_init(struct wasm_interp *interp, struct module *module)
{
	unsigned char *mem, *heap, *start;

	unsigned int ok, fns, errors_size, stack_size, locals_size,
	    callframes_size, resolver_size, labels_size, num_labels_size,
	    labels_capacity, memsize, memory_pages_size,
	    resolver_offsets_size, num_mems, globals_size, num_globals,
	    tables_size, elems_size, num_elements;

	memset(interp, 0, sizeof(*interp));

	interp->quitting = 0;
	interp->module = module;

	interp->module_inst.start_fn = -1;

	interp->prev_resolvers = 0;

	//stack = calloc(1, STACK_SPACE);
	fns = module->num_funcs;
	labels_capacity  = fns * MAX_LABELS;

	num_mems = was_section_parsed(module, section_memory)?
		module->memory_section.num_mems : 0;

	num_globals = was_section_parsed(module, section_global)?
		module->global_section.num_globals : 0;

	// TODO: make memory limits configurable
	errors_size      = 0xFFF;
	stack_size       = sizeof(struct val) * 0xFF;
 	labels_size      = labels_capacity * sizeof(struct label);
 	num_labels_size  = fns * sizeof(u16);
	resolver_offsets_size = sizeof(int) * 0xFF;
	callframes_size  = sizeof(struct callframe) * 0xFF;
	resolver_size    = sizeof(struct resolver) * MAX_LABELS;
	globals_size     = sizeof(struct global_inst) * num_globals;

	num_elements     = count_element_insts(module);
	elems_size       = num_elements * sizeof(struct elem_inst);
	locals_size      = calculate_locals_size(module);
	tables_size      = calculate_tables_size(module);

	if (num_mems > 1) {
		printf("more than one memory instance is not supported\n");
		return 0;
	}

	memory_pages_size = 256 * WASM_PAGE_SIZE;

	memsize =
		stack_size +
		errors_size +
		resolver_offsets_size +
		resolver_size +
		callframes_size +
		globals_size +
		num_globals +
		labels_size +
		num_labels_size +
		locals_size +
		tables_size +
		elems_size
		;

	mem = calloc(1, memsize);
	heap = malloc(memory_pages_size);

	make_cursor(mem, mem + memsize, &interp->mem);
	make_cursor(heap, heap + memory_pages_size, &interp->memory);

	// enable error reporting by default
	interp->errors.enabled = 1;

	start = interp->mem.p;

	ok = cursor_slice(&interp->mem, &interp->stack, stack_size);
	assert(interp->mem.p - start == stack_size);

	start = interp->mem.p;
	ok = ok && cursor_slice(&interp->mem, &interp->errors.cur, errors_size);
	assert(interp->mem.p - start == errors_size);

	start = interp->mem.p;
	ok = ok && cursor_slice(&interp->mem, &interp->resolver_offsets, resolver_offsets_size);
	assert(interp->mem.p - start == resolver_offsets_size);

	start = interp->mem.p;
	ok = ok && cursor_slice(&interp->mem, &interp->resolver_stack, resolver_size);
	assert(interp->mem.p - start == resolver_size);

	start = interp->mem.p;
	ok = ok && cursor_slice(&interp->mem, &interp->callframes, callframes_size);
	assert(interp->mem.p - start == callframes_size);

	interp->module_inst.num_globals = num_globals;

	start = interp->mem.p;
	ok = ok && (interp->module_inst.globals = cursor_alloc(&interp->mem, globals_size));
	assert(interp->mem.p - start == globals_size);

	start = interp->mem.p;
	ok = ok && (interp->module_inst.globals_init = cursor_alloc(&interp->mem, num_globals));
	assert(interp->mem.p - start == num_globals);

	start = interp->mem.p;
	ok = ok && cursor_slice(&interp->mem, &interp->labels, labels_size);
	assert(interp->mem.p - start == labels_size);

	start = interp->mem.p;
	ok = ok && alloc_tables(interp);
	assert(interp->mem.p - start == tables_size);

	start = interp->mem.p;
	ok = ok && cursor_slice(&interp->mem, &interp->num_labels, num_labels_size);
	assert(interp->mem.p - start == num_labels_size);

	start = interp->mem.p;
	ok = ok && alloc_locals(interp->module, &interp->mem, &interp->errors);
	assert(interp->mem.p - start == locals_size);

	interp->module_inst.num_elements = num_elements;

	start = interp->mem.p;
	ok = ok && (interp->module_inst.elements =
			cursor_alloc(&interp->mem, elems_size));
	assert(interp->mem.p - start == elems_size);

	/* init memory pages */
	assert((interp->mem.end - interp->mem.start) == memsize);

	if (!ok) {
		return interp_error(interp, "not enough memory");
	}

	return 1;
}

void wasm_parser_free(struct wasm_parser *parser)
{
	free(parser->mem.start);
}

void wasm_interp_free(struct wasm_interp *interp)
{
	free(interp->mem.start);
	free(interp->memory.start);
}

int interp_wasm_module(struct wasm_interp *interp)
{
	interp->ops = 0;

	if (interp->module->code_section.num_funcs == 0) {
		interp_error(interp, "empty module");
		return 0;
	}

	// reset cursors
	reset_cursor(&interp->stack);
	reset_cursor(&interp->resolver_stack);
	reset_cursor(&interp->resolver_offsets);
	reset_cursor(&interp->errors.cur);
	reset_cursor(&interp->callframes);

	// don't reset labels for perf!

	if (!reset_memory(interp))
		return interp_error(interp, "reset memory");

	if (!instantiate_module(interp))
		return interp_error(interp, "instantiate module");

	//interp->mem.p = interp->mem.start;

	if (call_function(interp, interp->module_inst.start_fn)) {
		debug("interp success!!\n");
	} else if (interp->quitting) {
		debug("finished running via process exit\n");
	} else {
		return interp_error(interp, "interp_code");
	}

	return 1;
}

int run_wasm(unsigned char *wasm, unsigned long len)
{
	struct wasm_parser p;
	struct wasm_interp interp;

	wasm_parser_init(&p, wasm, len, len * 16);

	if (!parse_wasm(&p)) {
		wasm_parser_free(&p);
		return 0;
	}

	if (!wasm_interp_init(&interp, &p.module)) {
		print_error_backtrace(&interp.errors);
		return 0;
	}

	if (!interp_wasm_module(&interp)) {
		print_error_backtrace(&interp.errors);
	}

	print_stack(&interp.stack);
	wasm_interp_free(&interp);
	wasm_parser_free(&p);

	return 1;
}
