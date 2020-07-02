
#include "io.h"
#include "parse.h"

#include <assert.h>

static void print_all_cells(struct parser *parser)
{
	struct cell *cell;
	int i, j;
	int ncells;

	ncells = cursor_index(parser->cells, sizeof(struct cell));
	printf("ncells %d\n", ncells);
	for (i = 0; i < ncells; i++) {
		cell = get_cell(parser->cells, i);
		print_cell(parser->attributes, cell);

		for (j = 0; j < cell->n_children; j++) {
			cell = get_cell(parser->cells, cell->children[j]);
			assert(cell);
			printf("  ");
			print_cell(parser->attributes, cell);
		}
	}
}

static int print_cell_tree(struct parser *parser, u16 root, int depth)
{
	int i;

	struct cell *cell = get_cell(parser->cells, root);
	if (!cell) return 0;

	for (i = 0; i < depth; i++) {
		printf("  ");
	}

	print_cell(parser->attributes, cell);

	for (i = 0; i < cell->n_children; i++) {
		print_cell_tree(parser, cell->children[i], depth+1);
	}


	return 1;
}

int main(int argc, const char *argv[]) {
	static u8 file_buf[4096];
	static u8 token_buf[2048];
	static u8 attrs_buf[4096];
	static u8 cells_buf[sizeof(struct cell) * 1024];

	struct cursor tokens;
	struct cursor attributes;
	struct cursor cells;

	struct parser parser;

	size_t count;
	const char *space;
	int ok;
	u16 root;

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

	print_cell_tree(&parser, root, 0);

	return 0;
}

