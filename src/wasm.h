
#ifndef PROTOVERSE_WASM_H
#define PROTOVERSE_WASM_H

static const unsigned char WASM_MAGIC[] = {0,'a','s','m'};

#define WASM_VERSION 0x01
#define MAX_U32_LEB128_BYTES 5
#define MAX_U64_LEB128_BYTES 10

#define FUNC_TYPE_TAG 0x60

#include "cursor.h"

enum valtype {
	i32 = 0x7F,
	i64 = 0x7E,
	f32 = 0x7D,
	f64 = 0x7C,
};

enum ref_instr {
	ref_null    = 0xD0,
	ref_is_null = 0xD1,
	ref_func    = 0xD2,
};

enum const_instr {
	const_i32 = 0x41,
	const_i64 = 0x42,
	const_f32 = 0x43,
	const_f64 = 0x44,
};

enum limit_type {
	limit_min = 0x00,
	limit_min_max = 0x01,
};

struct limits {
	unsigned int min;
	unsigned int max;
	enum limit_type type;
};

enum section_tag {
	section_custom,
	section_type,
	section_import,
	section_function,
	section_table,
	section_memory,
	section_global,
	section_export,
	section_start,
	section_element,
	section_code,
	section_data,
	num_sections,
};

enum reftype {
	funcref   = 0x70,
	externref = 0x6F,
};

struct resulttype {
	unsigned char *valtypes; /* enum valtype */
	int num_valtypes;
};

struct functype {
	struct resulttype params;
	struct resulttype result;
};

struct table {
	enum reftype reftype;
	struct limits limits;
};

struct tablesec {
	struct table *tables;
	int num_tables;
};

struct memsec {
	struct limits *mems; /* memtype */
	int num_mems;
};

struct funcsec {
	unsigned int *type_indices;
	int num_indices;
};

enum mut {
	mut_const,
	mut_var,
};

struct globaltype {
	enum valtype valtype;
	enum mut mut;
};

struct globalsec {
	struct global *globals;
	int num_globals;
};

struct typesec {
	struct functype *functypes;
	int num_functypes;
};

enum import_type {
	import_func,
	import_table,
	import_mem,
	import_global,
};

struct importdesc {
	enum import_type type;
	union {
		unsigned int typeidx;
		struct limits tabletype;
		struct limits memtype;
		struct globaltype globaltype;
	};
};

struct import {
	const char *module_name;
	const char *name;
	struct importdesc import_desc;
};

struct importsec {
	struct import *imports;
	int num_imports;
};

struct expr {
	unsigned char *code;
	int code_len;
};

struct global {
	struct globaltype type;
	struct expr init;
};

struct local {
	unsigned int n;
	enum valtype valtype;
};

/* "code" */
struct func {
	struct expr code;
	struct local *locals;
	int num_locals;
};

struct codesec {
	struct func *funcs;
	int num_funcs;
};

enum exportdesc {
	export_func,
	export_table,
	export_mem,
	export_global,
};

struct wexport {
	const char *name;
	unsigned int index;
	enum exportdesc desc;
};

struct exportsec {
	struct wexport *exports;
	int num_exports;
};

struct section {
	enum section_tag tag;
};

enum instr_tag {
	/* control instructions */
	i_unreachable   = 0x00,
	i_nop           = 0x01,
	i_block         = 0x02,
	i_loop          = 0x03,
	i_if            = 0x04,
	i_else          = 0x05,
	i_end           = 0x0B,
	i_br            = 0x0C,
	i_br_if         = 0x0D,
	i_br_table      = 0x0E,
	i_return        = 0x0F,
	i_call          = 0x10,
	i_call_indirect = 0x11,

	/* parametric instructions */
	i_drop          = 0x1A,
	i_select        = 0x1B,

	/* variable instructions */
	i_local_get     = 0x20,
	i_local_set     = 0x21,
	i_local_tee     = 0x22,
	i_global_get    = 0x23,
	i_global_set    = 0x24,

	/* memory instructions */
	i_i32_load      = 0x28,
	i_i64_load      = 0x29,
	i_f32_load      = 0x2A,
	i_f64_load      = 0x2B,
	i_i32_load8_s   = 0x2C,
	i_i32_load8_u   = 0x2D,
	i_i32_load16_s  = 0x2E,
	i_i32_load16_u  = 0x2F,
	i_i64_load8_s   = 0x30,
	i_i64_load8_u   = 0x31,
	i_i64_load16_s  = 0x32,
	i_i64_load16_u  = 0x33,
	i_i64_load32_s  = 0x34,
	i_i64_load32_u  = 0x35,
	i_i32_store     = 0x36,
	i_i64_store     = 0x37,
	i_f32_store     = 0x38,
	i_f64_store     = 0x39,
	i_i32_store8    = 0x3A,
	i_i32_store16   = 0x3B,
	i_i64_store8    = 0x3C,
	i_i64_store16   = 0x3D,
	i_i64_store32   = 0x3E,
	i_memory_size   = 0x3F,
	i_memory_grow   = 0x40,

	/* numeric instructions */
	i_i32_const     = 0x41,
	i_i64_const     = 0x42,
	i_f32_const     = 0x43,
	i_f64_const     = 0x44,

	i_i32_eqz       = 0x45,
	i_i32_eq        = 0x46,
	i_i32_ne        = 0x47,
	i_i32_lt_s      = 0x48,
	i_i32_lt_u      = 0x49,
	i_i32_gt_s      = 0x4A,
	i_i32_gt_u      = 0x4B,
	i_i32_le_s      = 0x4C,
	i_i32_le_u      = 0x4D,
	i_i32_ge_s      = 0x4E,
	i_i32_ge_u      = 0x4F,

	i_i64_eqz       = 0x50,
	i_i64_eq        = 0x51,
	i_i64_ne        = 0x52,
	i_i64_lt_s      = 0x53,
	i_i64_lt_u      = 0x54,
	i_i64_gt_s      = 0x55,
	i_i64_gt_u      = 0x56,
	i_i64_le_s      = 0x57,
	i_i64_le_u      = 0x58,
	i_i64_ge_s      = 0x59,
	i_i64_ge_u      = 0x5A,

	i_f32_eq        = 0x5B,
	i_f32_ne        = 0x5C,
	i_f32_lt        = 0x5D,
	i_f32_gt        = 0x5E,
	i_f32_le        = 0x5F,
	i_f32_ge        = 0x60,

	i_f64_eq        = 0x61,
	i_f64_ne        = 0x62,
	i_f64_lt        = 0x63,
	i_f64_gt        = 0x64,
	i_f64_le        = 0x65,
	i_f64_ge        = 0x66,

	i_i32_clz       = 0x67,

	i_i32_add       = 0x6A,
	i_i32_sub       = 0x6B,
	/* TODO: more instrs */

};

enum blocktype_tag {
	blocktype_empty,
	blocktype_valtype,
	blocktype_index,
};

struct blocktype {
	enum blocktype_tag tag;
	union {
		enum valtype valtype;
		unsigned int index;
	};
};

struct block_instr {
	struct blocktype blocktype;
	struct instr *instrs;
	int num_instrs;
};

struct instr {
	enum instr_tag tag;
	union {
		struct block_instr block;
	};
};

enum datamode {
	datamode_active,
	datamode_passive,
};

struct wdata_active {
	int mem_index;
	struct expr offset_expr;
};

struct wdata {
	struct wdata_active active;
	unsigned char *bytes;
	int bytes_len;
	enum datamode mode;
};

struct datasec {
	struct wdata *datas;
	int num_datas;
};

struct startsec {
	int start_fn;
};

struct module {
	unsigned int parsed;
	struct typesec type_section;
	struct funcsec func_section;
	struct importsec import_section;
	struct exportsec export_section;
	struct codesec code_section;
	struct tablesec table_section;
	struct memsec memory_section;
	struct globalsec global_section;
	struct startsec start_section;
	struct datasec data_section;
};

struct wasm_interp {
	struct module *module;
	size_t ops;

	struct cursor cur; /* code */
	struct cursor code_stack; /* struct cursor */
	struct cursor stack; /* struct val */
	struct cursor mem; /* u8/mixed */
	struct cursor locals;  /* struct val */
	struct cursor locals_offsets; /* int */

	struct parser_error *errors;
};

struct wasm_parser {
	struct module module;
	struct cursor cur;
	struct cursor mem;
	struct parse_error *errors;
};


int run_wasm(unsigned char *wasm, unsigned long len);
int parse_wasm(struct wasm_parser *p);
void wasm_interp_init(struct wasm_interp *interp);
void wasm_interp_free(struct wasm_interp *interp);
int interp_wasm_module(struct wasm_interp *interp, struct module *module);

#endif /* PROTOVERSE_WASM_H */
