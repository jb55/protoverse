
#ifndef PROTOVERSE_CURSOR_H
#define PROTOVERSE_CURSOR_H

#include "typedefs.h"
#include "varint.h"

#include <stdio.h>
#include <string.h>

#define unlikely(x)     __builtin_expect((x),0)

struct cursor {
	unsigned char *start;
	unsigned char *p;
	unsigned char *end;
};

struct array {
	struct cursor cur;
	unsigned int elem_size;
};

static inline void make_cursor(u8 *start, u8 *end, struct cursor *cursor)
{
	cursor->start = start;
	cursor->p = start;
	cursor->end = end;
}

static inline void make_array(struct array *a, u8* start, u8 *end, unsigned int elem_size)
{
	make_cursor(start, end, &a->cur);
	a->elem_size = elem_size;
}

static inline unsigned char *array_index(struct array *a, int ind)
{
	u8 *p = a->cur.start + a->elem_size * ind; 
	if (unlikely(p >= a->cur.end)) {
		return NULL;
	}
	return p;
}

static inline int cursor_eof(struct cursor *c)
{
	return c->p == c->end;
}

static inline void *cursor_alloc(struct cursor *mem, unsigned long size)
{
	void *ret;

	if (mem->p + size > mem->end) {
		return NULL;
	}

	ret = mem->p;
	memset(ret, 0, size);
	mem->p += size;

	return ret;
}

static inline void copy_cursor(struct cursor *src, struct cursor *dest)
{
	dest->start = src->start;
	dest->p = src->p;
	dest->end = src->end;
}

static inline int pull_byte(struct cursor *cursor, u8 *c)
{
	if (unlikely(cursor->p + 1 > cursor->end))
		return 0;

	*c = *cursor->p;
	cursor->p++;

	return 1;
}


static inline int push_byte(struct cursor *cursor, u8 c)
{
	if (unlikely(cursor->p + 1 > cursor->end)) {
		return 0;
	}

	*cursor->p = c;
	cursor->p++;

	return 1;
}

static inline int pull_data(struct cursor *cursor, u8 *data, int len)
{
	if (unlikely(cursor->p + len > cursor->end)) {
		return 0;
	}

	memcpy(data, cursor->p, len);
	cursor->p += len;

	return 1;
}

static inline int pull_data_into_cursor(struct cursor *cursor,
			  struct cursor *dest,
			  unsigned char **data,
			  int len)
{
	int ok;

	if (unlikely(dest->p + len > dest->end)) {
		printf("not enough room in dest buffer\n");
		return 0;
	}

	ok = pull_data(cursor, dest->p, len);
	if (!ok) return 0;

	*data = dest->p;
	dest->p += len;

	return 1;
}

static inline int cursor_pop(struct cursor *cur, u8 *data, int len)
{
	if (unlikely(cur->p - len < cur->start)) {
		printf("cursor_pop oob\n");
		return 0;
	}
	
	cur->p -= len;
	memcpy(cur->p, data, len);

	return 1;
}

static inline int cursor_push(struct cursor *cursor, u8 *data, int len)
{
	if (unlikely(cursor->p + len > cursor->end)) {
		printf("cursor_push oob\n");
		return 0;
	}

	memcpy(cursor->p, data, len);
	cursor->p += len;

	return 1;
}

static inline int cursor_push_int(struct cursor *cursor, int i)
{
	return cursor_push(cursor, (u8*)&i, sizeof(i));
}

static inline size_t cursor_count(struct cursor *cursor, size_t elem_size)
{
	return (cursor->p - cursor->start)/elem_size;
}

/* TODO: push_varint */
static inline int push_varint(struct cursor *cursor, int n)
{
	int ok, len;
	unsigned char b;
	len = 0;

	while (1) {
		b = (n & 0xFF) | 0x80;
		n >>= 7;
		if (n == 0) {
			b &= 0x7F;
			ok = push_byte(cursor, b);
			len++;
			if (!ok) return 0;
			break;
		}

		ok = push_byte(cursor, b);
		len++;
		if (!ok) return 0;
	}

	return len;
}

/* TODO: pull_varint */
static inline int pull_varint(struct cursor *cursor, int *n)
{
	int ok, i;
	unsigned char b;
	*n = 0;

	for (i = 0;; i++) {
		ok = pull_byte(cursor, &b);
		if (!ok) return 0;

		*n |= ((int)b & 0x7F) << (i * 7);

		/* is_last */
		if ((b & 0x80) == 0) {
			return i+1;
		}

		if (i == 4) return 0;
	}

	return 0;
}

static inline int pull_int(struct cursor *cursor, int *i)
{
	return pull_data(cursor, (u8*)i, sizeof(*i));
}

static inline int cursor_push_u16(struct cursor *cursor, u16 i)
{
	return cursor_push(cursor, (u8*)&i, sizeof(i));
}

static inline void *index_cursor(struct cursor *cursor, unsigned int index, int elem_size)
{
	u8 *p;
	p = &cursor->start[elem_size * index];

	if (unlikely(p > cursor->end))
		return NULL;

	return (void*)p;
}


static inline int push_sized_str(struct cursor *cursor, const char *str, int len)
{
	return cursor_push(cursor, (u8*)str, len);
}

static inline int push_str(struct cursor *cursor, const char *str)
{
	return cursor_push(cursor, (u8*)str, strlen(str));
}

static inline int push_c_str(struct cursor *cursor, const char *str)
{
	return push_str(cursor, str) && push_byte(cursor, 0);
}


/* TODO: push varint size */
static inline int push_prefixed_str(struct cursor *cursor, const char *str)
{
	int ok, len;
	len = strlen(str);
	ok = push_varint(cursor, len);
	if (!ok) return 0;
	return push_sized_str(cursor, str, len);
}

static inline int pull_prefixed_str(struct cursor *cursor, struct cursor *dest_buf, const char **str)
{
	int len, ok;

	ok = pull_varint(cursor, &len);
	if (!ok) return 0;

	if (unlikely(dest_buf->p + len > dest_buf->end)) {
		return 0;
	}

	ok = pull_data_into_cursor(cursor, dest_buf, (unsigned char**)str, len);
	if (!ok) return 0;

	ok = push_byte(dest_buf, 0);

	return 1;
}

static inline int cursor_remaining_capacity(struct cursor *cursor)
{
	return cursor->end - cursor->p;
}


#define max(a,b) ((a) > (b) ? (a) : (b))
static inline void cursor_print_around(struct cursor *cur, int range)
{
	unsigned char *c;

	c = max(cur->p - range, cur->start);
	for (; c < cur->end && c < (cur->p + range); c++) {
		printf("%02x", *c);
	}
	printf("\n");

	c = max(cur->p - range, cur->start);
	for (; c < cur->end && c < (cur->p + range); c++) {
		if (c == cur->p) {
			printf("^");
			continue;
		}
		printf("  ");
	}
	printf("\n");
}
#undef max

#endif
