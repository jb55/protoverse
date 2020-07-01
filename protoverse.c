
#include "io.h"
#include "parse.h"

#include <assert.h>

int main(int argc, const char *argv[]) {
	static u8 file_buf[4096];
	static u8 token_buf[2048];
	static u8 attrs_buf[4096];
	static u8 cells_buf[sizeof(struct cell) * 1024];

	struct cursor tokens;
	struct cursor attributes;
	struct cursor cells;

	struct cell *cell;

	struct parser parser;

	size_t count;
	const char *space;
	int ok, i;
	u16 root;
	int ncells;
	const char *name;
	int name_len;

	parser.tokens = &tokens;
	parser.attributes = &attributes;
	parser.cells = &cells;


	make_cursor(cells_buf, cells_buf + sizeof(cells_buf), &cells);
	make_cursor(attrs_buf, attrs_buf + sizeof(attrs_buf), &attributes);
	make_cursor(token_buf, token_buf + sizeof(token_buf), &tokens);

	space = argc == 2 ? argv[1] : "satoshis-citadel.space";
	ok = read_file(space, file_buf, sizeof(file_buf), &count);

	if (!ok) {
		printf("failed to load '%s'\n", space);
		return 1;
	}


	ok = tokenize_cells(file_buf, count, &tokens);

	if (!ok) {
		printf("failed to tokenize\n");
		return 1;
	}

	assert(tokens.p == token_buf);

	ok = parse_cell(&parser, &root);
	if (!ok) {
		print_token_error(&tokens);
	}

	ncells = cursor_index(&cells, sizeof(struct cell));
	printf("ncells %d\n", ncells);
	for (i = 0; i < ncells; i++) {
		name_len = 0;
		cell = get_cell(&cells, i);
		cell_name(&attributes, cell, &name, &name_len);
		printf("cell %s %.*s\n",
		       cell->type == C_OBJECT
		       ? object_type_str(cell->obj_type)
		       : cell_type_str(cell->type), name_len, name);
	}

	return 0;
}
