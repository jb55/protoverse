
#include "wasm.h"
#include "parser.h"
#include "debug.h"

#include <stdarg.h>
#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define note_error(p, fmt, ...) note_error_(p, "%s: " fmt, __FUNCTION__, ##__VA_ARGS__)
#define interp_error(p, fmt, ...) interp_error_(p, "%s: " fmt, __FUNCTION__, ##__VA_ARGS__)

#define ERR_STACK_SIZE 16
#define NUM_LOCALS 0xFFFF

static const int MAX_LABELS = 128;

struct parse_error {
	int pos;
	char *msg;
	struct parse_error *next;
};

struct val {
	enum valtype type;
	union {
		int i32;
		int64_t i64;
		float f32;
		double f64;
	};
};

static inline int is_valtype(unsigned char byte)
{
	switch ((enum valtype)byte) {
		case i32:
		case i64:
		case f32:
		case f64:
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

static const char *valtype_name(enum valtype valtype)
{
	switch (valtype) {
	case i32: return "i32";
	case i64: return "i64";
	case f32: return "f32";
	case f64: return "f64";
	}

	return "unk";
}

static void print_val(struct val *val)
{
	switch (val->type) {
	case i32: printf("%d", val->i32); break;
	case i64: printf("%ld", val->i64); break;
	case f32: printf("%f", val->f32); break;
	case f64: printf("%f", val->f64); break;
	}
	printf(":%s\n", valtype_name(val->type));
}

static inline int cursor_popdata(struct cursor *cur, unsigned char *dest, int len)
{
	if (cur->p - len < cur->start)
		return 0;

	cur->p -= len;

	if (dest)
		memcpy(dest, cur->p, len);

	return 1;
}

static inline int was_section_parsed(struct module *module,
	enum section_tag section)
{
	return module->parsed & (1 << section);
}

static inline int cursor_popval(struct cursor *cur, struct val *val)
{
	return cursor_popdata(cur, (unsigned char*)val, sizeof(*val));
}

static void print_stack(struct cursor *stack)
{
	struct val val;
	int i;
	u8 *p = stack->p;

	for (i = 0; stack->p > stack->start; i++) {
		cursor_popval(stack, &val);
		printf("[%d] ", i);
		print_val(&val);
	}

	stack->p = p;
}

static inline int array_push(struct array *a, void *data)
{
	return cursor_push(&a->cur, (u8*)data, a->elem_size);
}

static inline int array_pop_u32(struct array *a, u32 *out)
{
	return cursor_pop(&a->cur, (u8*)out, a->elem_size);
}

static inline int cursor_pushval(struct cursor *cur, struct val *val)
{
	return cursor_push(cur, (u8*)val, sizeof(*val));
}

static inline int cursor_push_callframe(struct cursor *cur, struct callframe *frame)
{
	return cursor_push(cur, (u8*)frame, sizeof(*frame));
}

static inline struct callframe *top_callframe(struct cursor *cur)
{
	assert(cur->p > cur->start);
	return ((struct callframe*)cur->p) - 1;
}

static inline struct cursor *interp_codeptr(struct wasm_interp *interp)
{
	struct callframe *frame;
	frame = top_callframe(&interp->callframes);
	if (!frame) return 0;
	return &frame->code;
}

static inline int cursor_pop_callframe(struct cursor *cur, struct callframe *frame)
{
	return cursor_popdata(cur, (unsigned char*)frame, sizeof(*frame));
}

static inline int cursor_popint(struct cursor *cur, int *i)
{
	return cursor_popdata(cur, (unsigned char *)i, sizeof(int));
}

static inline int offset_stack_top(struct cursor *cur)
{
	int *p = (int*)cur->p;

	if (cur->p == cur->start) {
		return 0;
	}

	return *(p - sizeof(*p));
}

static void interp_error_(struct wasm_interp *p, const char *fmt, ...)
{
	va_list ap;

	(void)p;
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	fprintf(stderr, "\n");
	va_end(ap);
}

static void note_error_(struct wasm_parser *p, const char *fmt, ...)
{
	static char buf[512];
	struct parse_error err;
	struct parse_error *perr, *new_err;

	va_list ap;
	va_start(ap, fmt);
	vsprintf(buf, fmt, ap);
	va_end(ap);

	perr = NULL;
	err.msg = (char*)p->mem.p;
	err.pos = p->cur.p - p->cur.start;
	err.next = NULL;

	if (!push_c_str(&p->mem, buf)) {
		fprintf(stderr, "arena OOM when recording parse error, ");
		fprintf(stderr, "mem->p at %ld, remaining %ld, strlen %ld\n",
				p->mem.p - p->mem.start,
				p->mem.end - p->mem.p,
				strlen(buf));
		return;
	}

	new_err = (struct parse_error *)p->mem.p;

	if (!cursor_push(&p->mem, (unsigned char*)&err, sizeof(err))) {
		fprintf(stderr, "arena OOM when pushing data, ");
		fprintf(stderr, "mem->p at %ld, remaining %ld, data size %ld\n",
				p->mem.p - p->mem.start,
				p->mem.end - p->mem.p,
				sizeof(err));
		return;
	}

	for (perr = p->errors; perr != NULL;) {
		if (perr == NULL || perr->next == NULL)
			break;
		perr = perr->next;
	}

	if (p->errors == NULL) {
		p->errors = new_err;
	} else {
		perr->next = new_err;
	}
}

static void print_parse_backtrace(struct wasm_parser *p)
{
	struct parse_error *err;
	for (err = p->errors; err != NULL; err = err->next) {
		fprintf(stderr, "%08x:%s\n", err->pos, err->msg);
	}
}

static void print_functype(struct functype *ft)
{
	int i;

	for (i = 0; i < ft->params.num_valtypes; i++) {
		printf("%s ", valtype_name(ft->params.valtypes[i]));
	}
	printf("-> ");
	for (i = 0; i < ft->result.num_valtypes; i++) {
		printf("%s ", valtype_name(ft->result.valtypes[i]));
	}
	printf("\n");
}

static void print_type_section(struct typesec *typesec)
{
	int i;
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
	int i;
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

static const char *reftype_name(enum reftype reftype)
{
	switch (reftype) {
	case funcref: return "funcref";
	case externref: return "externref";
	}
	return "unknown_reftype";
}

static void print_memory_section(struct memsec *memory)
{
	int i;
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
	int i;
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

static const char *get_function_name(struct module *module, unsigned int func_index)
{
	struct wexport *export;
	int i;

	for (i = 0; i < module->export_section.num_exports; i++) {
		export = &module->export_section.exports[i];
		if (export->index == func_index) {
			return export->name;
		}
	}

	return "unknown";
}

static void print_start_section(struct module *module)
{
	int fn = module->start_section.start_fn;
	printf("start function: %d <%s>\n", fn, get_function_name(module, fn));
}

static void print_export_section(struct exportsec *exportsec)
{
	int i;
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

static void print_func(struct func *func)
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

static void print_section(struct module *module, enum section_tag section)
{
	switch (section) {
	case section_custom:
		printf("TODO: print custom section\n");
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
		printf("TODO: print element section\n");
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
	int i;
	enum section_tag section;

	for (i = 0; i < num_sections; i++) {
		section = (enum section_tag)i;
		if (was_section_parsed(module, section)) {
			print_section(module, section);
		}
	}
}


/* I DONT NEED THIS (yet?) */
/*
static int leb128_write(struct cursor *write, unsigned int val)
{
	unsigned char byte;
	while (1) {
		byte = value & 0x7F;
		value >>= 7;
		if (value == 0) {
			if (!push_byte(write, byte))
				return 0;
			return 1;
		} else {
			if (!push_byte(write, byte | 0x80))
				return 0;
		}
	}
}
*/

#define BYTE_AT(type, i, shift) (((type)(p[i]) & 0x7f) << (shift))
#define LEB128_1(type) (BYTE_AT(type, 0, 0))
#define LEB128_2(type) (BYTE_AT(type, 1, 7) | LEB128_1(type))
#define LEB128_3(type) (BYTE_AT(type, 2, 14) | LEB128_2(type))
#define LEB128_4(type) (BYTE_AT(type, 3, 21) | LEB128_3(type))
#define LEB128_5(type) (BYTE_AT(type, 4, 28) | LEB128_4(type))

static int leb128_read(struct cursor *read, unsigned int *val)
{
	unsigned char p[5];
	unsigned char *start;

	start = read->p;
	*val = 0;

	if (pull_byte(read, &p[0]) && (p[0] & 0x80) == 0) {
		*val = LEB128_1(unsigned int);
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
	}

	/* reset if we're missing */
	read->p = start;
	return 0;
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

	if (!pull_byte(&p->cur, (unsigned char*)valtype)) {
		note_error(p, "valtype tag oob");
		return 0;
	}

	if (is_valtype((unsigned char)*valtype))
		return 1;

	p->cur.p = start;
	note_error(p, "%c is not a valid valtype tag", *valtype);
	return 0;
}

static int parse_result_type(struct wasm_parser *p, struct resulttype *rt)
{
	int i, elems;
	enum valtype valtype;
	unsigned char *start;

	rt->num_valtypes = 0;
	rt->valtypes = 0;
	start = p->mem.p;

	if (!leb128_read(&p->cur, (unsigned int*)&elems)) {
		note_error(p, "vec len");
		return 0;
	}

	for (i = 0; i < elems; i++)
	{
		if (!parse_valtype(p, &valtype)) {
			note_error(p, "valtype #%d", i);
			p->mem.p = start;
			return 0;
		}

		if (!push_byte(&p->mem, (unsigned char)valtype)) {
			note_error(p, "valtype push data OOM #%d", i);
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
	if (!consume_byte(&p->cur, FUNC_TYPE_TAG)) {
		note_error(p, "type tag");
		return 0;
	}

	if (!parse_result_type(p, &func->params)) {
		note_error(p, "params");
		return 0;
	}

	if (!parse_result_type(p, &func->result)) {
		note_error(p, "result");
		return 0;
	}

	return 1;
}

static int parse_name(struct wasm_parser *p, const char **name)
{
	unsigned int bytes;
	if (!leb128_read(&p->cur, &bytes)) {
		note_error(p, "name len");
		return 0;
	}

	if (!pull_data_into_cursor(&p->cur, &p->mem, (unsigned char**)name,
				bytes)) {
		note_error(p, "name string");
		return 0;
	}

	if (!push_byte(&p->mem, 0)) {
		note_error(p, "name null byte");
		return 0;
	}

	return 1;
}

static int parse_export_desc(struct wasm_parser *p, enum exportdesc *desc)
{
	unsigned char byte;

	if (!pull_byte(&p->cur, &byte)) {
		note_error(p, "export desc byte eof");
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

	note_error(p, "invalid tag: %x", byte);
	return 0;
}

static int parse_export(struct wasm_parser *p, struct wexport *export)
{
	if (!parse_name(p, &export->name)) {
		note_error(p, "export name");
		return 0;
	}

	if (!parse_export_desc(p, &export->desc)) {
		note_error(p, "export desc");
		return 0;
	}

	if (!leb128_read(&p->cur, &export->index)) {
		note_error(p, "export index");
		return 0;
	}

	return 1;
}

static int parse_local(struct wasm_parser *p, struct local *local)
{
	if (!leb128_read(&p->cur, &local->n)) {
		note_error(p, "n");
		return 0;
	}

	if (!parse_valtype(p, &local->valtype)) {
		note_error(p, "valtype");
		return 0;
	}

	return 1;
}

static int parse_vector(struct wasm_parser *p, unsigned int item_size,
		unsigned int *elems, void **items)
{
	if (!leb128_read(&p->cur, elems)) {
		note_error(p, "len");
		return 0;
	}

	*items = cursor_alloc(&p->mem, *elems * item_size);

	if (*items == NULL) {
		note_error(p, "vector alloc oom");
		return 0;
	}

	return 1;
}

static int parse_func(struct wasm_parser *p, struct func *func)
{
	unsigned int elems, size, i;
	unsigned char *start;
	struct local *locals;

	if (!leb128_read(&p->cur, &size)) {
		note_error(p, "code size");
		return 0;
	}

	start = p->cur.p;

	if (!parse_vector(p, sizeof(*locals), &elems, (void**)&locals)) {
		note_error(p, "locals");
		return 0;
	}

	for (i = 0; i < elems; i++) {
		if (!parse_local(p, &locals[i])) {
			note_error(p, "local #%d", i);
			return 0;
		}
	}

	func->locals = locals;
	func->num_locals = elems;
	func->code.code_len = size - (p->cur.p - start);

	if (!pull_data_into_cursor(&p->cur, &p->mem, &func->code.code,
				func->code.code_len)) {
		note_error(p, "code oom");
		return 0;
	}

	assert(func->code.code[func->code.code_len-1] == i_end);

	return 1;
}

static int parse_code_section(struct wasm_parser *p,
		struct codesec *code_section)
{
	struct func *funcs;
	unsigned int elems, i;

	if (!parse_vector(p, sizeof(*funcs), &elems, (void**)&funcs)) {
		note_error(p, "funcs");
		return 0;
	}

	for (i = 0; i < elems; i++) {
		if (!parse_func(p, &funcs[i])) {
			note_error(p, "func #%d", i);
			return 0;
		}
	}

	code_section->num_funcs = elems;
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
		note_error(p, "reftype");
		return 0;
	}

	if (!is_valid_reftype(tag)) {
		note_error(p, "invalid reftype: 0x%x", reftype);
		return 0;
	}

	*reftype = (enum reftype)tag;

	return 1;
}


static int parse_export_section(struct wasm_parser *p,
		struct exportsec *export_section)
{
	struct wexport *exports;
	unsigned int elems, i;

	if (!parse_vector(p, sizeof(*exports), &elems, (void**)&exports)) {
		note_error(p, "vector");
		return 0;
	}

	for (i = 0; i < elems; i++) {
		if (!parse_export(p, &exports[i])) {
			note_error(p, "export #%d", i);
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
		note_error(p, "oob");
		return 0;
	}

	if (tag != limit_min && tag != limit_min_max) {
		note_error(p, "invalid tag %02x", tag);
		return 0;
	}

	if (!leb128_read(&p->cur, &limits->min)) {
		note_error(p, "min");
		return 0;
	}

	if (tag == limit_min)
		return 1;

	if (!leb128_read(&p->cur, &limits->max)) {
		note_error(p, "max");
		return 0;
	}

	return 1;
}

static int parse_table(struct wasm_parser *p, struct table *table)
{
	if (!parse_reftype(p, &table->reftype)) {
		note_error(p, "reftype");
		return 0;
	}

	if (!parse_limits(p, &table->limits)) {
		note_error(p, "limits");
		return 0;
	}

	return 1;
}

static inline int is_valid_ref_instr(u8 tag)
{
	switch ((enum ref_instr)tag) {
	case ref_null: return 1;
	case ref_is_null: return 1;
	case ref_func: return 1;
	}
	return 0;
}

static inline int is_valid_const_instr(u8 tag)
{
	switch ((enum const_instr)tag) {
	case const_i32: return 1;
	case const_i64: return 1;
	case const_f32: return 1;
	case const_f64: return 1;
	}
	return 0;
}

static int parse_const_instr(struct wasm_parser *p)
{
	u8 tag;
	unsigned int n;

	if (!pull_byte(&p->cur, &tag)) {
		note_error(p, "tag");
		return 0;
	}

	if (!is_valid_const_instr(tag)) {
		note_error(p, "invalid const instr tag 0x%x", tag);
		p->cur.p--;
		return 0;
	}

	switch ((enum const_instr)tag) {
	case const_i32:
	case const_i64:
		if (!leb128_read(&p->cur, &n)) {
			note_error(p, "couldn't read integer");
			return 0;
		}
		break;
	case const_f32:
	case const_f64:
		note_error(p, "TODO parse float constants");
		return 0;
	}

	return 1;
}

static int parse_ref_instr(struct wasm_parser *p)
{
	u8 tag;
	unsigned int idx;

	if (!pull_byte(&p->cur, &tag)) {
		note_error(p, "tag");
		return 0;
	}

	if (!is_valid_ref_instr(tag)) {
		//note_error(p, "invalid ref instr tag 0x%x", tag);
		p->cur.p--;
		return 0;
	}

	switch ((enum ref_instr)tag) {
	case ref_null:
		if (!parse_reftype(p, (enum reftype*)&tag)) {
			note_error(p, "invalid ref.null instr reftype 0x%x", tag);
			return 0;
		}
		break;

	case ref_is_null:
		break;

	case ref_func:
		if (!leb128_read(&p->cur, &idx)) {
			note_error(p, "invalid ref.func idx");
			return 0;
		}
		break;
	}

	return 1;
}

static inline int parse_const_expr_instr(struct wasm_parser *p)
{
	return parse_ref_instr(p) || parse_const_instr(p);
}

static int parse_const_expr(struct wasm_parser *p, struct expr *expr)
{
	expr->code = p->cur.p;

	while (p->cur.p < p->cur.end) {
		if (*p->cur.p == i_end) {
			p->cur.p++;
			expr->code_len = p->cur.p - expr->code;
			return 1;
		}

		if (!parse_const_expr_instr(p)) {
			note_error(p, "no constant expr found");
			return 0;
		}
	}

	return 0;
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

	note_error(p, "unknown mut %02x", *p->cur.p);
	return 0;
}

static int parse_globaltype(struct wasm_parser *p, struct globaltype *g)
{
	if (!parse_valtype(p, &g->valtype)) {
		note_error(p, "valtype");
		return 0;
	}

	return parse_mut(p, &g->mut);
}

static int parse_global(struct wasm_parser *p,
		struct global *global)
{
	if (!parse_globaltype(p, &global->type)) {
		note_error(p, "type");
		return 0;
	}

	if (!parse_const_expr(p, &global->init)) {
		note_error(p, "init code");
		return 0;
	}

	return 1;
}

static int parse_global_section(struct wasm_parser *p,
		struct globalsec *global_section)
{
	struct global *globals;
	unsigned int elems, i;

	if (!parse_vector(p, sizeof(*globals), &elems, (void**)&globals)) {
		note_error(p, "globals vector");
		return 0;
	}

	for (i = 0; i < elems; i++) {
		if (!parse_global(p, &globals[i])) {
			note_error(p, "global #%d/%d", i+1, elems);
			return 0;
		}
	}

	global_section->num_globals = elems;
	global_section->globals = globals;

	return 1;
}

static int parse_memory_section(struct wasm_parser *p,
		struct memsec *memory_section)
{
	struct limits *mems;
	unsigned int elems, i;

	if (!parse_vector(p, sizeof(*mems), &elems, (void**)&mems)) {
		note_error(p, "mems vector");
		return 0;
	}

	for (i = 0; i < elems; i++) {
		if (!parse_limits(p, &mems[i])) {
			note_error(p, "memory #%d/%d", i+1, elems);
			return 0;
		}
	}

	memory_section->num_mems = elems;
	memory_section->mems = mems;

	return 1;
}

static int parse_start_section(struct wasm_parser *p,
		struct startsec *start_section)
{
	if (!leb128_read(&p->cur, (unsigned int*)&start_section->start_fn)) {
		note_error(p, "start_fn index");
		return 0;
	}

	return 1;
}

static inline int parse_byte_vector(struct wasm_parser *p, unsigned char **data,
		int *data_len)
{
	if (!leb128_read(&p->cur, (unsigned int*)data_len)) {
		note_error(p, "len");
		return 0;
	}

	if (p->cur.p + *data_len > p->cur.end) {
		note_error(p, "byte vector overflow");
		return 0;
	}

	*data = p->cur.p;
	p->cur.p += *data_len;

	return 1;
}

static int parse_wdata(struct wasm_parser *p, struct wdata *data)
{
	u8 tag;

	if (!pull_byte(&p->cur, &tag)) {
		note_error(p, "tag");
		return 0;
	}

	if (tag > 2) {
		cursor_print_around(&p->cur, 10);
		note_error(p, "invalid datasegment tag: 0x%x", tag);
		return 0;
	}

	switch (tag) {
	case 0:
		data->mode = datamode_active;
		data->active.mem_index = 0;

		if (!parse_const_expr(p, &data->active.offset_expr)) {
			note_error(p, "const expr");
			return 0;
		}

		if (!parse_byte_vector(p, &data->bytes, &data->bytes_len)) {
			note_error(p, "bytes vector");
			return 0;
		}

		break;

	case 1:
		data->mode = datamode_passive;

		if (!parse_byte_vector(p, &data->bytes, &data->bytes_len)) {
			note_error(p, "passive bytes vector");
			return 0;
		}

		break;

	case 2:
		data->mode = datamode_active;

		if (!leb128_read(&p->cur, (unsigned int*)&data->active.mem_index))  {
			note_error(p, "read active data mem_index");
			return 0;
		}

		if (!parse_const_expr(p, &data->active.offset_expr)) {
			note_error(p, "read active data (w/ mem_index) offset_expr");
			return 0;
		}

		if (!parse_byte_vector(p, &data->bytes, &data->bytes_len)) {
			note_error(p, "active (w/ mem_index) bytes vector");
			return 0;
		}

		break;
	}

	return 1;
}

static int parse_data_section(struct wasm_parser *p, struct datasec *section)
{
	struct wdata *data;
	unsigned int elems, i;

	if (!parse_vector(p, sizeof(*data), &elems, (void**)&data)) {
		note_error(p, "datas vector");
		return 0;
	}

	for (i = 0; i < elems; i++) {
		if (!parse_wdata(p, &data[i])) {
			note_error(p, "data segment #%d/%d", i+1, elems);
			return 0;
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
	unsigned int elems, i;

	if (!parse_vector(p, sizeof(*tables), &elems, (void**)&tables)) {
		note_error(p, "tables vector");
		return 0;
	}

	for (i = 0; i < elems; i++) {
		if (!parse_table(p, &tables[i])) {
			note_error(p, "table #%d/%d", i+1, elems);
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
	unsigned int *indices;
	unsigned int i, elems;

	if (!parse_vector(p, sizeof(*indices), &elems, (void**)&indices)) {
		note_error(p, "indices");
		return 0;
	}

	for (i = 0; i < elems; i++) {
		if (!leb128_read(&p->cur, &indices[i])) {
			note_error(p, "typeidx #%d", i);
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
		note_error(p, "elemtype != 0x70");
		return 0;
	}

	if (!parse_limits(p, limits)) {
		note_error(p, "limits");
		return 0;
	}

	return 1;
}

static int parse_importdesc(struct wasm_parser *p, struct importdesc *desc)
{
	unsigned char tag;

	if (!pull_byte(&p->cur, &tag)) {
		note_error(p, "oom");
		return 0;
	}

	desc->type = (enum import_type)tag;

	switch (desc->type) {
	case import_func:
		if (!leb128_read(&p->cur, &desc->typeidx)) {
			note_error(p, "typeidx");
			return 0;
		}
		return 1;

	case import_table:
		return parse_import_table(p, &desc->tabletype);

	case import_mem:
		if (!parse_limits(p, &desc->memtype)) {
			note_error(p, "memtype limits");
			return 0;
		}

		return 1;

	case import_global:
		if (!parse_globaltype(p, &desc->globaltype)) {
			note_error(p, "globaltype");
			return 0;
		}

		return 1;
	}

	note_error(p, "unknown importdesc tag %02x", tag);
	return 0;
}

static int parse_import(struct wasm_parser *p, struct import *import)
{
	if (!parse_name(p, &import->module_name)) {
		note_error(p, "module name");
		return 0;
	}

	if (!parse_name(p, &import->name)) {
		note_error(p, "name");
		return 0;
	}

	if (!parse_importdesc(p, &import->import_desc)) {
		note_error(p, "desc");
		return 0;
	}

	return 1;
}

static int parse_import_section(struct wasm_parser *p, struct importsec *importsec)
{
	unsigned int elems, i;
	struct import *imports;

	if (!parse_vector(p, sizeof(*imports), &elems, (void**)&imports)) {
		note_error(p, "imports");
		return 0;
	}

	for (i = 0; i < elems; i++) {
		if (!parse_import(p, &imports[i])) {
			note_error(p, "import #%d", i);
			return 0;
		}
	}

	importsec->imports = imports;
	importsec->num_imports = elems;

	return 1;
}

/* type section is just a vector of function types */
static int parse_type_section(struct wasm_parser *p, struct typesec *typesec)
{
	unsigned int elems, i;
	struct functype *functypes;

	typesec->num_functypes = 0;
	typesec->functypes = NULL;

	if (!parse_vector(p, sizeof(*functypes), &elems, (void**)&functypes)) {
		note_error(p, "functypes");
		return 0;
	}

	for (i = 0; i < elems; i++) {
		if (!parse_func_type(p, &functypes[i])) {
			note_error(p, "functype #%d", i);
			return 0;
		}
	}

	typesec->functypes = functypes;
	typesec->num_functypes = elems;

	return 1;
}

static int parse_section_by_tag(struct wasm_parser *p, enum section_tag tag,
		unsigned int size)
{
	(void)size;
	switch (tag) {
	case section_custom:
		note_error(p, "section_custom parse not implemented");
		return 0;
	case section_type:
		if (!parse_type_section(p, &p->module.type_section)) {
			note_error(p, "type section");
			return 0;
		}
		return 1;
	case section_import:
		if (!parse_import_section(p, &p->module.import_section)) {
			note_error(p, "import section");
			return 0;
		}
		return 1;
	case section_function:
		if (!parse_function_section(p, &p->module.func_section)) {
			note_error(p, "function section");
			return 0;
		}
		return 1;
	case section_table:
		if (!parse_table_section(p, &p->module.table_section)) {
			note_error(p, "table section");
			return 0;
		}
		return 1;
	case section_memory:
		if (!parse_memory_section(p, &p->module.memory_section)) {
			note_error(p, "memory section");
			return 0;
		}
		return 1;
	case section_global:
		if (!parse_global_section(p, &p->module.global_section)) {
			note_error(p, "global section");
			return 0;
		}
		return 1;
	case section_export:
		if (!parse_export_section(p, &p->module.export_section)) {
			note_error(p, "export section");
			return 0;
		}
		return 1;
	case section_start:
		if (!parse_start_section(p, &p->module.start_section)) {
			note_error(p, "start section");
			return 0;
		}
		return 1;
	case section_element:
		note_error(p, "section_element parse not implemented");
		return 0;
	case section_code:
		if (!parse_code_section(p, &p->module.code_section)) {
			note_error(p, "code section");
			return 0;
		}
		return 1;
	case section_data:
		if (!parse_data_section(p, &p->module.data_section)) {
			note_error(p, "data section");
			return 0;
		}
		return 1;
	default:
		note_error(p, "invalid section tag");
		return 0;
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
	unsigned int bytes;

	if (!parse_section_tag(&p->cur, &tag)) {
		note_error(p, "section tag");
		return 2;
	}

	if (!leb128_read(&p->cur, &bytes)) {
		note_error(p, "section len");
		return 0;
	}

	if (!parse_section_by_tag(p, tag, bytes)) {
		note_error(p, "%s (%d bytes)", section_name(tag), bytes);
		return 0;
	}

	p->module.parsed |= 1 << tag;

	return 1;
}

int parse_wasm(struct wasm_parser *p)
{
	p->module.parsed = 0;

	if (!consume_bytes(&p->cur, WASM_MAGIC, sizeof(WASM_MAGIC))) {
		note_error(p, "magic");
		goto fail;
	}

	if (!consume_u32(&p->cur, WASM_VERSION)) {
		note_error(p, "version");
		goto fail;
	}

	while (1) {
		if (cursor_eof(&p->cur))
			break;

		if (!parse_section(p)) {
			note_error(p, "section");
			goto fail;
		}
	}

	debug("module parse success!\n\n");
	print_module(&p->module);
	return 1;

fail:
	debug("parse failure backtrace:\n");
	print_parse_backtrace(p);
	debug("\npartially parsed module:\n");
	print_module(&p->module);
	return 0;
}

static int interp_prep_binop(struct wasm_interp *interp, struct val *a,
		struct val *b, struct val *c, enum valtype typ)
{
	c->type = typ;

	if (!cursor_popval(&interp->stack, a)) {
		interp_error(interp, "couldn't pop first val");
		return 0;
	}

	if (!cursor_popval(&interp->stack, b)) {
		interp_error(interp, "couldn't pop second val");
		return 0;
	}

	if (a->type != typ || b->type != typ) {
	        interp_error(interp, "type mismatch, %s != %s",
			valtype_name(a->type), valtype_name(b->type));
	        return 0;
	}

	return 1;
}

static int interp_i32_add(struct wasm_interp *interp)
{
	struct val a, b, c;

	if (!interp_prep_binop(interp, &a, &b, &c, i32)) {
		interp_error(interp, "add prep");
		return 0;
	}

	c.i32 = a.i32 + b.i32;

	return cursor_pushval(&interp->stack, &c);
}

static int interp_i32_sub(struct wasm_interp *interp)
{
	struct val a, b, c;

	if (!interp_prep_binop(interp, &a, &b, &c, i32)) {
		interp_error(interp, "sub prep");
		return 0;
	}

	c.i32 = a.i32 - b.i32;

	return cursor_pushval(&interp->stack, &c);
}

static inline struct val *get_local(struct wasm_interp *interp, int ind)
{
	struct val *p;
	int offset = offset_stack_top(&interp->locals_offsets);

	if (!(p = index_cursor(&interp->locals, offset + ind, sizeof(struct val)))) {
		interp_error(interp, "%d local oob %d > %ld", ind, offset + ind,
				interp->locals.end - interp->locals.start);
		return NULL;
	}
	return p;
}

static inline int count_locals(struct wasm_interp *interp)
{
	int offset = offset_stack_top(&interp->locals_offsets);
	int count = cursor_count(&interp->locals, sizeof(struct val));
	return count - offset;
}

static int set_local(struct wasm_interp *interp, int ind, struct val *val)
{
	struct val *local;
	int nlocals;

	nlocals = count_locals(interp);

	if (ind > nlocals) {
		/* TODO: if we hit this then we need to push empty locals up to the index */
		interp_error(interp, "local index out of order");
		return 0;
	}

	if (ind < nlocals) {
		debug("memsetting local %d\n", ind);
		if (!(local = get_local(interp, ind))) {
			return 0;
		}
		memcpy(local, val, sizeof(*val));
		return 1;
	}

	cursor_pushval(&interp->locals, val);
	assert(count_locals(interp) > 0);
	return 1;
}

static int interp_local_set(struct wasm_interp *interp)
{
	struct val val;
	unsigned int index;

	if (!cursor_popval(&interp->stack, &val)) {
		interp_error(interp, "pop");
		return 0;
	}

	if (!leb128_read(interp_codeptr(interp), &index)) {
		interp_error(interp, "read index");
		return 0;
	}

	if (!set_local(interp, index, &val)) {
		interp_error(interp, "set local");
		return 0;
	}

	return 1;
}

static int interp_local_get(struct wasm_interp *interp)
{
	unsigned int index;
	unsigned int nlocals;
	struct val *val;

	if (!leb128_read(interp_codeptr(interp), &index)) {
		interp_error(interp, "index");
		return 0;
	}

	nlocals = count_locals(interp);
	if (index >= nlocals) {
		interp_error(interp, "local %d not set (%d locals)", index,
				nlocals);
		return 0;
	}

	if (!(val = get_local(interp, index))) {
		interp_error(interp, "get local");
		return 0;
	}

	return cursor_pushval(&interp->stack, val);
}

static inline void make_i32_val(struct val *val, int v)
{
	val->type = i32;
	val->i32 = v;
}

static inline int interp_i32_gt_u(struct wasm_interp *interp)
{
	struct val a, b, c;

	if (!interp_prep_binop(interp, &a, &b, &c, i32)) {
		interp_error(interp, "gt_u prep");
		return 0;
	}

	c.i32 = (unsigned int)a.i32 > (unsigned int)b.i32;

	return cursor_pushval(&interp->stack, &c);
}

static inline int interp_i32_const(struct wasm_interp *interp)
{
	struct val val;
	unsigned int read;

	if (!leb128_read(interp_codeptr(interp), &read)) {
		interp_error(interp, "invalid constant value");
		return 0;
	}

	make_i32_val(&val, read);

	return cursor_pushval(&interp->stack, &val);
}

static inline int imports_count(struct module *module)
{
	return !was_section_parsed(module, section_import) ? 0 :
		module->import_section.num_imports;
}

static inline int code_count(struct module *module)
{
	// I guess not having any code and is technically possible?
	return !was_section_parsed(module, section_code) ? 0 :
		module->code_section.num_funcs;
}

static inline int functions_count(struct module *module)
{
	return imports_count(module) + code_count(module);
}

static inline struct func *get_function(struct module *module, int ind)
{
	// TODO: imports
	if (ind >= module->code_section.num_funcs) {
		return NULL;
	}

	return &module->code_section.funcs[ind - imports_count(module)];
}

static inline struct functype *get_function_type(struct module *module, int ind)
{
	if (ind >= module->func_section.num_indices) {
		return NULL;
	}

	ind = module->func_section.type_indices[ind - imports_count(module)];
	if (ind >= module->type_section.num_functypes) {
		return NULL;
	}

	return &module->type_section.functypes[ind];
}

static int prepare_call(struct wasm_interp *interp, int func_index)
{
	int i;
	struct functype *functype;
	struct func *func;
	struct val val;
	struct callframe callframe;
	enum valtype paramtype;
	unsigned int offset;

	debug("calling %s\n", get_function_name(interp->module, func_index));

	if (!(func = get_function(interp->module, func_index))) {
		interp_error(interp, "function %d oob/not found (%d funcs)",
				func_index,
				interp->module->code_section.num_funcs);
		return 0;
	}

	/* record locals offset for indexing locals in the next function */
	offset = cursor_count(&interp->locals, sizeof(struct val));
	if (!cursor_push_int(&interp->locals_offsets, offset)) {
		interp_error(interp, "push locals offset");
		return 0;
	}

	/* get type signature to know how many locals to push as params */
	if (!(functype = get_function_type(interp->module, func_index))) {
		interp_error(interp, "couldn't get function type");
		return 0;
	}


	/* push params as locals */
	for (i = 0; i < functype->params.num_valtypes; i++) {
		paramtype = (enum valtype)functype->params.valtypes[i];

		if (!cursor_popval(&interp->stack, &val)) {
			interp_error(interp, "not enough arguments for call");
			return 0;
		}

		if (val.type != paramtype) {
			interp_error(interp,
				"call parameter %d type mismatch. got %s, expected %s",
				i+1,
				valtype_name(val.type),
				valtype_name(paramtype));
			return 0;
		}

		if (!cursor_pushval(&interp->locals, &val)) {
			interp_error(interp, "push param local");
			return 0;
		}
	}

	/* update current function and push it to the callframe as well */
	make_cursor(func->code.code, func->code.code + func->code.code_len, &callframe.code);
	callframe.fn = func_index;

	if (!cursor_push_callframe(&interp->callframes, &callframe)) {
		interp_error(interp, "oob cursor_pushcode");
		return 0;
	}

	return 1;
}

int interp_code(struct wasm_interp *interp);

static int interp_call(struct wasm_interp *interp)
{
	unsigned int func_index;

	if (!leb128_read(interp_codeptr(interp), &func_index)) {
		interp_error(interp, "read func index");
		return 0;
	}

	if (!prepare_call(interp, func_index)) {
		interp_error(interp, "prepare");
		return 0;
	}

	/* call the function! */
	return interp_code(interp);
}


static int parse_blocktype(struct cursor *cur, struct blocktype *blocktype)
{
	unsigned char byte;

	if (!pull_byte(cur, &byte)) {
		cursor_print_around(cur, 10);
		printf("parse_blocktype: oob\n");
		return 0;
	}

	if (byte == 0x40) {
		blocktype->tag = blocktype_empty;
	} else if (is_valtype(byte)) {
		blocktype->tag = blocktype_valtype;
		blocktype->valtype = (enum valtype)byte;
	} else {
		blocktype->tag = blocktype_index;
		cur->p--;

		if (!leb128_read(cur, &blocktype->type_index)) {
			printf("parse_blocktype: read type_index\n");
			return 0;
		}
	}

	return 1;
}

// if we don't have a resolved label, we need to recursively consume
// instructions until we get to the i_end or i_else, etc
static int consume_instr(struct wasm_interp *interp, u8 *tag)
{
	u8 byte;

	if (!pull_byte(&interp->cur, tag)) {
		interp_error(interp, "oob");
		return 0;
	}

	switch ((enum instr_tag)*tag) {
		// two-byte instrs
		case i_memory_size:
		case i_memory_grow:
			return pull_byte(&interp->cur, &byte);

		case i_block:
		case i_loop:
		case i_if:
		case i_else:
		case i_end:
		case i_br:
		case i_br_if:
		case i_br_table:
		case i_call:
		case i_call_indirect:
		case i_local_get:
		case i_local_set:
		case i_local_tee:
		case i_global_get:
		case i_global_set:
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
		case i_i32_const:
		case i_i64_const:
		case i_f32_const:
		case i_f64_const:
			interp_error(interp, "consume dynamic-size op");
			return 0;

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
			return 1;
	}

	interp_error(interp, "unhandled tag: 0x%x", *tag);
	return 0;
}

static inline struct label *index_label(struct array *a, int fn, int ind)
{
	return (struct label*)array_index(a, (MAX_LABELS * fn) + ind);
}

static inline int label_is_resolved(struct label *label)
{
	return label->instr_pos & 0x80000000;
}

static int resolve_label(struct wasm_interp *interp)
{
	struct label *label;
	struct callframe *frame;
	u32 label_ind = 0;

	if (!cursor_pop(&interp->resolver_stack, (u8*)&label_ind, sizeof(label_ind))) {
		interp_error(interp, "couldn't pop jump resolver stack");
		return 0;
	}

	frame = top_callframe(&interp->callframes);
	assert(frame);

	label = index_label(&interp->labels, frame->fn, label_ind);
	assert(label);
	assert(!label_is_resolved(label));

	label->jump = interp->cur.p - interp->cur.start;
	label->instr_pos |= 0x80000000;

	return 1;
}

// consume instructions to resolve labels
static int consume_instrs_until(struct wasm_interp *interp, u8 stop_instr)
{
	u8 tag = 0;

	for (;;) {
		if (!consume_instr(interp, &tag)) {
			interp_error(interp, "consume 0x%x", tag);
			return 0;
		}

		if (tag == stop_instr) {
			resolve_label(interp);
			return 1;
		}
	}
}

static inline u32 label_instr_pos(struct label *label)
{
	return label->instr_pos & 0x7FFFFFFF;
}

static inline void set_label_pos(struct label *label, u32 pos)
{
	assert(!(pos & 0x80000000));
	label->instr_pos = pos;
}

static inline u16 *func_num_labels(struct wasm_interp *interp, int fn)
{
	u16 *num = (u16*)array_index(&interp->num_labels, fn);
	assert(num);
	assert(*num <= MAX_LABELS);
	return num;
}

static int find_label(struct wasm_interp *interp, int fn, u32 instr_pos)
{
	u16 *num_labels, i;
	struct label *label;

	num_labels = func_num_labels(interp, fn);
	label = index_label(&interp->labels, fn, 0);
	assert(label);
	
	for (i = 0; i < *num_labels; label++) {
		assert((u8*)label < interp->labels.cur.end);
		if (label_instr_pos(label) == instr_pos)
			return i;
		i++;
	}

	return -1;
}

// upsert an unresolved label
static int upsert_label(struct wasm_interp *interp, int fn, u32 instr_pos, int *ind)
{
	struct label *label;
	u16 *num_labels;

	num_labels = func_num_labels(interp, fn);

	if (*num_labels > 0 && ((*ind = find_label(interp, fn, instr_pos)) == 0)) {
		// we already have the label
		return 1;
	}

	if (*num_labels + 1 > MAX_LABELS) {
		interp_error(interp, "too many labels in %s (> %d)",
			get_function_name(interp->module, fn), MAX_LABELS);
		return 0;
	}

	*ind = *num_labels;
	label = index_label(&interp->labels, fn, *ind);
	assert(label);

	set_label_pos(label, instr_pos);
	*num_labels = *num_labels + 1;

	return 2;
}

static int branch_jump(struct wasm_interp *interp, u8 end_tag)
{
	u32 instr_pos;
	int ind;

	int fns;
	struct label *label;
	struct callframe *frame;

	fns = functions_count(interp->module);
	frame = top_callframe(&interp->callframes);

	assert(frame);
	assert(frame->fn < fns);
	assert(interp->cur.start == frame->code.start);

	label = index_label(&interp->labels, frame->fn, 0);
	assert(label);

	if (label_is_resolved(label)) {
		interp->cur.p = interp->cur.start + label->jump;
		assert(interp->cur.p < interp->cur.end);
		return 1;
	}

	instr_pos = interp->cur.p - interp->cur.start;
	if (!upsert_label(interp, frame->fn, instr_pos, &ind)) {
		interp_error(interp, "upsert label");
		return 0;
	}

	if (!cursor_push_u16(&interp->resolver_stack, ind)) {
		interp_error(interp, "push label index to resolver stack oob");
		return 0;
	}

	// consume instructions, use resolver stack to resolve jumps
	if (!consume_instrs_until(interp, end_tag)) {
		interp_error(interp, "consume instrs");
		return 0;
	}

	return 1;
}

static int interp_if(struct wasm_interp *interp)
{
	struct val cond;
	struct blocktype blocktype;

	if (!parse_blocktype(&interp->cur, &blocktype)) {
		interp_error(interp, "couldn't parse blocktype");
		return 0;
	}

	if (!cursor_popval(&interp->stack, &cond)) {
		interp_error(interp, "if pop val");
		return 0;
	}

	if (cond.i32 == 1) {
		return 1;
	}

	if (!branch_jump(interp, i_end)) {
		return 0;
	}

	return 0;
}

static int interp_instr(struct wasm_interp *interp, unsigned char tag)
{
	interp->ops++;
	debug("executing 0x%0x\n", tag);

	switch (tag) {
	case i_unreachable: return 1;
	case i_nop: return 1;
	case i_local_get: return interp_local_get(interp);
	case i_local_set: return interp_local_set(interp);
	case i_i32_add: return interp_i32_add(interp);
	case i_i32_sub: return interp_i32_sub(interp);
	case i_i32_const: return interp_i32_const(interp);
	case i_i32_gt_u: return interp_i32_gt_u(interp);
	case i_if: return interp_if(interp);
	case i_call: return interp_call(interp);
	default:
		    interp_error(interp, "unhandled instruction 0x%x", tag);
		    return 0;
	}

	return 0;
}

int interp_code(struct wasm_interp *interp)
{
	struct callframe frame;
	unsigned char tag;
	int offset;

	for (;;) {
		if (!pull_byte(interp_codeptr(interp), &tag)) {
			cursor_print_around(interp_codeptr(interp), 10);
			interp_error(interp, "instr tag");
			return 0;
		}

		if (tag == i_end) {
			cursor_pop_callframe(&interp->callframes, &frame);
			cursor_popint(&interp->locals_offsets, &offset);
			break;
		}

		if (!interp_instr(interp, tag)) {
			interp_error(interp, "interp instr");
			return 0;
		}
	}

	return 1;
}

#define STACK_SPACE 5242880
#define MEM_SPACE 5242880
#define LOCALS_SPACE 5242880

static int find_function(struct module *module, const char *name)
{
	struct wexport *export;
	int i;

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
	if (module->parsed & (1 << section_start)) {
		return module->start_section.start_fn;
	}

	return find_function(module, "start");
}

static int cursor_slice(struct cursor *mem, struct cursor *slice, size_t size)
{
	u8 *p;
	if (!(p = cursor_alloc(mem, size))) {
		return 0;
	}
	make_cursor(p, mem->p, slice);
	return 1;
}

static inline int array_alloc(struct cursor *mem, struct array *a, int elems)
{
	return cursor_slice(mem, &a->cur, elems * a->elem_size);
}

void wasm_interp_init(struct wasm_interp *interp)
{
	static unsigned char *stack, *mem;

	interp->ops = 0;

	stack = malloc(STACK_SPACE);
	mem = malloc(MEM_SPACE);

	make_cursor(stack, stack + STACK_SPACE, &interp->stack);
	make_cursor(mem, mem + MEM_SPACE, &interp->mem);
}

void wasm_interp_free(struct wasm_interp *interp)
{
	free(interp->stack.start);
	free(interp->mem.start);
}

static int alloc_labels(struct wasm_interp *interp, int fns)
{
	const int capacity = fns * MAX_LABELS;

	interp->labels.elem_size = sizeof(struct label);
	interp->num_labels.elem_size = sizeof(u16);

	return array_alloc(&interp->mem, &interp->labels, capacity) &&
	       array_alloc(&interp->mem, &interp->num_labels, fns);

}

int interp_wasm_module(struct wasm_interp *interp, struct module *module)
{
	int ok, func, fns;

	interp->module = module;
	interp->ops = 0;

	if (module->code_section.num_funcs == 0) {
		interp_error(interp, "empty module");
		return 0;
	}

	// reset cursors
	interp->stack.p = interp->stack.start;
	interp->mem.p = interp->mem.start;

	fns = functions_count(module);

	ok =
		cursor_slice(&interp->mem, &interp->locals,
			     sizeof(struct val) * NUM_LOCALS) &&
		cursor_slice(&interp->mem, &interp->locals_offsets, sizeof(int) * 255) &&
		cursor_slice(&interp->mem, &interp->callframes, sizeof(struct callframe) * 255) &&
		cursor_slice(&interp->mem, &interp->resolver_stack, sizeof(u32) * MAX_LABELS) &&
		alloc_labels(interp, fns);

	assert(ok);

	func = find_start_function(module);
	if (func == -1) {
		interp_error(interp, "no start function found");
		return 0;
	}

	if (!prepare_call(interp, func)) {
		interp_error(interp, "preparing start function");
		return 0;
	}

	if (interp_code(interp)) {
		debug("interp success!!\n");
	}

	debug("ops: %ld\nstack:\n", interp->ops);
	print_stack(&interp->stack);

	return ok;
}

int run_wasm(unsigned char *wasm, unsigned long len)
{
	struct wasm_parser p;
	struct wasm_interp interp;

	void *mem;
	int ok, arena_size;

	arena_size = len * 16;
	memset(&p, 0, sizeof(p));
	mem = malloc(arena_size);
	assert(mem);

	make_cursor(wasm, wasm + len, &p.cur);
	make_cursor(mem, mem + arena_size, &p.mem);

	if (!parse_wasm(&p)) {
		free(mem);
		return 0;
	}

	wasm_interp_init(&interp);
	ok = interp_wasm_module(&interp, &p.module);
	wasm_interp_free(&interp);

	free(mem);
	return ok;
}
