
#include "describe.h"
#include <assert.h>
#include <stdio.h>

#define ADJ_PUSHED 1
#define ADJ_NOT_PUSHED 2

/* various functions used to describe the scene */

struct describe {
	struct cell *cell;
	struct parser *parsed;
	struct cursor *strs;
};

static int push_adjective(struct cursor *strs, struct attribute *attr)
{
	int ok;

	switch (attr->type) {
	case A_CONDITION:
		ok = push_str(strs, " ");
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
	return attr->type == A_CONDITION;
}

static int count_adjectives(struct describe *desc)
{
	struct attribute *attr;
	int count;
	int i;

	for (i = 0, count = 0; i < desc->cell->n_attributes; i++) {
		attr = get_attr(desc->parsed->attributes,
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
		attr = get_attr(desc->parsed->attributes,
				desc->cell->attributes[i]);
		assert(attr);

		if (!is_adjective(attr))
			continue;

		if (adjs > 0) {
			if (adjs == adj_count-1)
				push_str(desc->strs, " and");
			else if (adjs != adj_count-1)
				push_str(desc->strs, ",");

		}

		ok = push_adjective(desc->strs, attr);
		if (ok == ADJ_PUSHED)
			adjs++;
	}

	return 1;
}

static int push_made_of(struct describe *desc)
{
	struct attribute *attr;
	int i, ok;

	for (i = 0; i < desc->cell->n_attributes; i++) {
		attr = get_attr(desc->parsed->attributes,
				desc->cell->attributes[i]);
		assert(attr);

		if (attr->type == A_MATERIAL) {
			ok = push_str(desc->strs, " made of ");
			if (!ok) return 0;

			ok = push_sized_str(desc->strs,
					    attr->data.str.ptr,
					    attr->data.str.len);
			if (!ok) return 0;
			return 1;
		}
	}

	return 2;
}

static int push_named(struct describe *desc)
{
	const char *name;
	int name_len;
	int ok;

	cell_name(desc->parsed->attributes, desc->cell, &name, &name_len);

	if (name_len == 0)
		return 1;

	ok = push_str(desc->strs, " named ");
	if (!ok) return 0;

	ok = push_sized_str(desc->strs, name, name_len);
	if (!ok) return 0;

	return 1;
}

static int describe_room(struct describe *desc)
{
	int ok;

	/* TODO: temp buffers for determining a(n) things */
	ok = push_str(desc->strs, "a(n)");
	if (!ok) return 0;

	ok = push_adjectives(desc);
	if (!ok) return 0;

	ok = push_str(desc->strs, " room");
	if (!ok) return 0;

	ok = push_made_of(desc);
	if (!ok) return 0;

	ok = push_named(desc);
	if (!ok) return 0;

	return 1;
}

static int describe_group(struct describe *desc)
{
	(void)desc;
	return 0;
}

static int describe_object(struct describe *desc)
{
	(void)desc;
	return 0;
}

static int describe_space(struct describe *desc)
{
	(void)desc;
	return 0;
}

int describe_cell(struct cell *cell, struct parser *parsed, struct cursor *strbuf)
{
	struct describe desc;

	desc.cell = cell;
	desc.parsed = parsed;
	desc.strs = strbuf;

	switch (cell->type) {
	case C_ROOM:
		return describe_room(&desc);
	case C_GROUP:
		return describe_group(&desc);
	case C_OBJECT:
		return describe_object(&desc);
	case C_SPACE:
		return describe_space(&desc);
	}

	return 1;
}
