
#include "describe.h"
#include <assert.h>
#include <stdio.h>
#include <ctype.h>
#include <string.h>

#define ADJ_PUSHED 1
#define ADJ_NOT_PUSHED 2

/* various functions used to describe the scene */

static int push_sized_word(struct cursor *strs, const char *str, int len)
{
	if (strs->p-1 >= strs->start && !isspace(*(strs->p-1))) {
		if (!cursor_push_str(strs, " "))
			return 0;
	}

	if (!push_sized_str(strs, str, len))
		return 0;

	return 1;
}

static int push_word(struct cursor *strs, const char *str)
{
	return push_sized_word(strs, str, strlen(str));
}

static int push_adjective(struct cursor *strs, struct attribute *attr)
{
	int ok;

	switch (attr->type) {
	case A_COLOR:
	case A_CONDITION:
		ok = cursor_push_str(strs, " ");
		if (!ok) return 0;
		ok = push_sized_str(strs, attr->data.str.ptr,
				    attr->data.str.len);
		if (!ok) return 0;
		return ADJ_PUSHED;
	default:
		break;
	}

	return ADJ_NOT_PUSHED;
}

static int is_adjective(struct attribute *attr)
{
	return attr->type == A_CONDITION || attr->type == A_COLOR;
}

static int count_adjectives(struct describe *desc)
{
	struct attribute *attr;
	int count;
	int i;

	for (i = 0, count = 0; i < desc->cell->n_attributes; i++) {
		attr = get_attr(&desc->parsed->attributes,
				desc->cell->attributes[i]);
		assert(attr);

		if (is_adjective(attr))
			count++;
	}

	return count;
}

static int push_adjectives(struct describe *desc)
{
	struct attribute *attr;
	int i, ok, adjs, adj_count;

	adj_count = count_adjectives(desc);

	for (i = 0, adjs = 0; i < desc->cell->n_attributes; i++) {
		attr = get_attr(&desc->parsed->attributes,
				desc->cell->attributes[i]);
		assert(attr);

		if (!is_adjective(attr))
			continue;

		if (adjs > 0) {
			if (adjs == adj_count-1) {
				ok = push_word(desc->strs, "and");
				if (!ok) return 0;
			}
			else if (adjs != adj_count-1) {
				ok = cursor_push_str(desc->strs, ",");
				if (!ok) return 0;
			}

		}

		ok = push_adjective(desc->strs, attr);
		if (ok == ADJ_PUSHED)
			adjs++;
	}

	return 1;
}

static int find_attr(struct cursor *attrs, struct cell *cell,
		     enum attribute_type type, struct attribute **attr)
{
	int i;

	for (i = 0; i < cell->n_attributes; i++) {
		*attr = get_attr(attrs, cell->attributes[i]);
		assert(*attr);

		if ((*attr)->type == type)
			return 1;
	}

	return 0;
}

static int push_made_of(struct describe *desc)
{
	struct attribute *attr;
	int ok;

	ok = find_attr(&desc->parsed->attributes, desc->cell,
		       A_MATERIAL, &attr);
	if (!ok) return 2;

	ok = push_word(desc->strs, "made of");
	if (!ok) return 0;

	ok = push_sized_word(desc->strs, attr->data.str.ptr,
			       attr->data.str.len);
	if (!ok) return 0;
	return 1;
}

static int push_named(struct describe *desc)
{
	const char *name;
	int name_len;
	int ok;

	cell_attr_str(&desc->parsed->attributes, desc->cell, &name, &name_len,
			A_NAME);

	if (name_len == 0)
		return 1;

	ok = push_word(desc->strs, "named");
	if (!ok) return 0;

	ok = push_sized_word(desc->strs, name, name_len);
	if (!ok) return 0;

	return 1;
}

static int push_shape(struct describe *desc)
{
	struct attribute *attr;
	int ok;

	ok = find_attr(&desc->parsed->attributes, desc->cell, A_SHAPE, &attr);
	if (!ok) return 2;

	switch (attr->data.shape) {
	case SHAPE_RECTANGLE:
		push_word(desc->strs, "rectangular");
		break;
	case SHAPE_CIRCLE:
		push_word(desc->strs, "circular");
		break;
	case SHAPE_SQUARE:
		push_word(desc->strs, "square");
		break;
	}

	return 1;
}

static int describe_detail(struct describe *desc, const char *name)
{
	int ok;

	/* TODO: temp buffers for determining a(n) things */
	ok = cursor_push_str(desc->strs, "There is a(n)");
	if (!ok) return 0;

	ok = push_adjectives(desc);
	if (!ok) return 0;

	ok = push_shape(desc);
	if (!ok) return 0;

	ok = push_word(desc->strs, name);
	if (!ok) return 0;

	ok = push_made_of(desc);
	if (!ok) return 0;

	ok = push_named(desc);
	if (!ok) return 0;

	return 1;
}

static int describe_amount(struct describe *desc, int nobjs)
{
	int ok;

	if (nobjs == 1) {
		ok = push_word(desc->strs, "a single");
		if (!ok) return 0;
	} else if (nobjs == 2) {
		ok = push_word(desc->strs, "a couple of");
		if (!ok) return 0;
	} else if (nobjs == 3) {
		ok = push_word(desc->strs, "three");
		if (!ok) return 0;
	} else if (nobjs == 4) {
		ok = push_word(desc->strs, "four");
		if (!ok) return 0;
	} else if (nobjs == 5) {
		ok = push_word(desc->strs, "five");
		if (!ok) return 0;
	} else {
		ok = push_word(desc->strs, "many");
		if (!ok) return 0;
	}

	return 1;
}

static int describe_object_name(struct cursor *strs,
		struct cursor *attrs, struct cell *cell)
{
	const char *name;
	int name_len;

	cell_attr_str(attrs, cell, &name, &name_len, A_NAME);
	if (name_len > 0 && !push_sized_word(strs, name, name_len))
		return 0;

	if (cell->type == C_OBJECT) {
		if (cell->obj_type == O_OBJECT)
			return 1;
		return push_word(strs, object_type_str(cell->obj_type));
	}

	return push_word(strs, cell_type_str(cell->type));
}

static int describe_group_children(struct cell *parent, struct describe *desc)
{
	int i;
	struct cell *child;

	if (!push_word(desc->strs, "a"))
		return 0;

	for (i = 0; i < parent->n_children; i++) {
		child = get_cell(&desc->parsed->cells, parent->children[i]);
		assert(child);

		if (i > 0) {
			if (i == parent->n_children-1) {
				if (!push_word(desc->strs, "and"))
					return 0;
			}
			else if (i != parent->n_children-1) {
				if (!cursor_push_str(desc->strs, ","))
					return 0;
			}

		}

		if (!describe_object_name(desc->strs, &desc->parsed->attributes, child))
			return 0;
	}

	return 1;
}

static int describe_group(struct describe *desc)
{
	if (!describe_amount(desc, desc->cell->n_children))
		return 0;

	if (!push_word(desc->strs, "object"))
		return 0;

	if (desc->cell->n_children > 1) {
		if (!cursor_push_str(desc->strs, "s:"))
			return 0;
	}
	else {
		if (!cursor_push_str(desc->strs, ":"))
			return 0;
	}

	return describe_group_children(desc->cell, desc);
}

static int describe_object(struct describe *desc)
{
	return describe_object_name(desc->strs, &desc->parsed->attributes,
			desc->cell);
}

static int describe_object_detailed(struct describe *desc)
{
	if (!cursor_push_byte(desc->strs, 'A'))
		return 0;

	if (!push_adjectives(desc))
		return 0;

	if (!push_shape(desc))
		return 0;

	if (!describe_object_name(desc->strs, &desc->parsed->attributes, desc->cell))
		return 0;

	if (!push_made_of(desc))
		return 0;

	return 1;
}

int describe_cell(struct describe *desc)
{
	switch (desc->cell->type) {
	case C_ROOM:
		return describe_detail(desc, "room");
	case C_SPACE:
		return describe_detail(desc, "space");
	case C_GROUP:
		return describe_group(desc);
	case C_OBJECT:
		return describe_object(desc);
	}

	return 1;
}

static int describe_cell_detailed(struct describe *desc)
{
	switch (desc->cell->type) {
	case C_ROOM:
	case C_SPACE:
	case C_GROUP:
		return describe_cell(desc);
	case C_OBJECT:
		return describe_object_detailed(desc);
	}

	return 0;
}


static int describe_cell_name(struct describe *desc)
{
	if (desc->cell->type == C_OBJECT)
		return describe_object(desc);

	return push_word(desc->strs, cell_type_str(desc->cell->type));
}

static int describe_cell_children(struct describe *desc);

static int describe_cell_children_rest(struct describe desc)
{
	int i;
	struct cell *parent = desc.cell; 

	for (i = 0; i < parent->n_children; i++) {
		desc.cell = get_cell(&desc.parsed->cells, parent->children[i]);

		if (desc.cell->n_children > 0 && !describe_cell_children(&desc))
			return 0;
	}

	return 1;
}

static int describe_cell_children_group(struct describe desc)
{
	struct cell *child;

	if (desc.cell->n_children == 1 && 
	    (child = get_cell(&desc.parsed->cells, desc.cell->children[0])) &&
	    child->type == C_GROUP) {
		desc.cell = child;
		return describe_cell_children_group(desc);
	}

	if (!describe_group_children(desc.cell, &desc))
		return 0;

	if (!cursor_push_byte(desc.strs, '\n'))
		return 0;

	return describe_cell_children_rest(desc);
}

static int describe_cell_children(struct describe *desc)
{
	if (!push_word(desc->strs, "The"))
		return 0;

	if (!describe_cell_name(desc))
		return 0;

	if (!push_word(desc->strs, "contains"))
		return 0;

	return describe_cell_children_group(*desc);
}

int describe_cells(struct describe *desc)
{
	if (!describe_cell_detailed(desc))
		return 0;

	if (!cursor_push_str(desc->strs, ".\n"))
		return 0;

	if (desc->cell->n_children == 0)
		return 1;

	return describe_cell_children(desc);
}


int describe(struct parser *parser, u16 root_cell)
{
	static char strbuf[4096*32];
	struct cursor strs;
	struct cell *cell;
	struct describe desc;

	strbuf[0] = 0;

	cell = get_cell(&parser->cells, root_cell);

	make_cursor((u8*)strbuf, (u8*)strbuf + sizeof(strbuf), &strs);

	desc.cell = cell;
	desc.parsed = parser;
	desc.strs = &strs;

	describe_cells(&desc);

	printf("\n\ndescription\n-----------\n\n%s\n", strbuf);

	return 1;
}
