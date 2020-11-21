
#ifndef PROTOVERSE_CURSOR_H
#define PROTOVERSE_CURSOR_H

struct cursor {
	unsigned char *start;
	unsigned char *p;
	unsigned char *end;
};


void *cursor_alloc(struct cursor *mem, unsigned long size);
void copy_cursor(struct cursor *src, struct cursor *dest);
int cursor_index(struct cursor *cursor, int elem_size);
void make_cursor(unsigned char *start, unsigned char *end, struct cursor *cursor);
int cursor_remaining_capacity(struct cursor *cursor);
void *index_cursor(struct cursor *cursor, unsigned short index, int elem_size);

int push_u16(struct cursor *cursor, unsigned short i);
int push_int(struct cursor *cursor, int i);
int push_varint(struct cursor *cursor, int i);
int push_data(struct cursor *cursor, unsigned char *data, int len);
int push_byte(struct cursor *cursor, unsigned char c);

int pull_data_into_cursor(struct cursor *cursor, struct cursor *dest, unsigned char **data, int len);
int pull_data(struct cursor *cursor, unsigned char *data, int len);
int pull_byte(struct cursor *cursor, unsigned char *c);
int pull_int(struct cursor *cursor, int *i);
int pull_varint(struct cursor *cursor, int *i);

int push_prefixed_str(struct cursor *cursor, const char *str);
int push_str(struct cursor *cursor, const char *str);
int push_sized_str(struct cursor *cursor, const char *str, int len);

int pull_prefixed_str(struct cursor *cursor, struct cursor *dest_buf, const char **str);

#endif
