
#include "wasm.h"
#include "parser.h"

#include <stdarg.h>
#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>

#define note_error(p, fmt, ...) note_error_(p, "%s: " fmt, __FUNCTION__, ##__VA_ARGS__)

#define ERR_STACK_SIZE 16

struct parse_error {
	int pos;
	char *msg;
	struct parse_error *next;
};

struct wasm_parser {
	struct module module;
	struct cursor cur;
	struct cursor mem;
	struct parse_error *errors;
};

#ifdef DEBUG
static void log_dbg_(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
}

#define log_dbg(...) log_dbg_(__VA_ARGS__)
#else
#define log_dbg(...)
#endif


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

	if (!push_str(&p->mem, buf)) {
		fprintf(stderr, "arena OOM when recording parse error, ");
		fprintf(stderr, "mem->p at %ld, remaining %ld, strlen %ld\n", 
				p->mem.p - p->mem.start, 
				p->mem.end - p->mem.p, 
				strlen(buf));
		return;
	}

	new_err = (struct parse_error *)p->mem.p;

	if (!push_data(&p->mem, (unsigned char*)&err, sizeof(err))) {
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

static void print_module(struct module *module)
{
	int i;
	printf("%d functypes:\n", module->type_section.num_functypes);
	for (i = 0; i < module->type_section.num_functypes; i++) {
		print_functype(&module->type_section.functypes[i]);
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

static int parse_valtype(struct wasm_parser *p, unsigned char *valtype)
{
	unsigned char *start;

	start = p->cur.p;

	if (!pull_byte(&p->cur, valtype)) {
		note_error(p, "valtype tag oob");
		return 0;
	}

	switch ((enum valtype)*valtype) {
	case i32:
	case i64:
	case f32:
	case f64:
		return 1;
	}

	p->cur.p = start;
	note_error(p, "%c is not a valid valtype tag", *valtype);
	return 0;
}

static int parse_result_type(struct wasm_parser *p, struct resulttype *rt)
{
	int i, elems;
	unsigned char valtype;
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

		if (!push_byte(&p->mem, valtype)) {
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


/* type section is just a vector of function types */
static int parse_type_section(struct wasm_parser *p, struct typesec *typesec)
{
	unsigned int elems, i;
	struct functype *functypes;

	typesec->num_functypes = 0;
	typesec->functypes = NULL;

	if (!leb128_read(&p->cur, &elems)) {
		note_error(p, "functypes vec len");
		return 0;
	}

	functypes = cursor_alloc(&p->mem, elems * sizeof(struct functype));
	
	if (!functypes) {
		/* can't use note_error because we're oom */
		fprintf(stderr, "could not allocate memory for type section\n");
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

static int parse_section_by_tag(struct wasm_parser *p, 
		enum section_tag tag, unsigned int size)
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
		note_error(p, "section_import parse not implemented");
		return 0;
	case section_function:
		note_error(p, "section_function parse not implemented");
		return 0;
	case section_table:
		note_error(p, "section_table parse not implemented");
		return 0;
	case section_memory:
		note_error(p, "section_memory parse not implemented");
		return 0;
	case section_global:
		note_error(p, "section_global parse not implemented");
		return 0;
	case section_export:
		note_error(p, "section_export parse not implemented");
		return 0;
	case section_start:
		note_error(p, "section_start parse not implemented");
		return 0;
	case section_element:
		note_error(p, "section_element parse not implemented");
		return 0;
	case section_code:
		note_error(p, "section_code parse not implemented");
		return 0;
	case section_data:
		note_error(p, "section_data parse not implemented");
		return 0;
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
		return 0;
	}

	if (!leb128_read(&p->cur, &bytes)) {
		note_error(p, "section len");
		return 0;
	}

	if (!parse_section_by_tag(p, tag, bytes)) {
		note_error(p, "%s (%d bytes)", section_name(tag), bytes);
		return 0;
	}

	return 1;
}

static int parse_wasm(struct wasm_parser *p)
{
	if (!consume_bytes(&p->cur, WASM_MAGIC, sizeof(WASM_MAGIC))) {
		note_error(p, "magic");
		goto fail;
	}

	if (!consume_u32(&p->cur, WASM_VERSION)) {
		note_error(p, "version");
		goto fail;
	}

	while (1) {
		if (!parse_section(p)) {
			note_error(p, "section");
			goto fail;
		}
	}

	return 1;

fail:
	printf("parse failure backtrace:\n");
	print_parse_backtrace(p);
	printf("\npartially parsed module:\n");
	print_module(&p->module);
	return 0;
}

int run_wasm(unsigned char *wasm, unsigned long len) 
{
	struct wasm_parser p;

	void *mem;
	int ok, arena_size;

	arena_size = len * 16;
	memset(&p, 0, sizeof(p));
	mem = malloc(arena_size);
	assert(mem);

	make_cursor(wasm, wasm + len, &p.cur);
	make_cursor(mem, mem + arena_size, &p.mem);

	ok = parse_wasm(&p);
	free(mem);
	return ok;
}
