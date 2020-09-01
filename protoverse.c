
#include "io.h"
#include "parse.h"
#include "describe.h"
#include "serve.h"
#include "client.h"

#include <assert.h>
#include <string.h>

#define streq(a, b) strcmp(a,b) == 0

/*
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
*/

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

static int parse_file(struct parser *parser, const char *filename, u16 *root)
{
	/* TODO: increase these limits */
	static u8 file_buf[4096];
	static u8 token_buf[2048];
	static u8 attrs_buf[sizeof(struct attribute) * 1024];
	static u8 cells_buf[sizeof(struct cell) * 1024];

	struct token_cursor tokens;
	struct cursor attributes;
	struct cursor cells;

	size_t count;
	int ok;

	parser->tokens = &tokens;
	parser->attributes = &attributes;
	parser->cells = &cells;

	make_cursor(cells_buf, cells_buf + sizeof(cells_buf), &cells);
	make_cursor(attrs_buf, attrs_buf + sizeof(attrs_buf), &attributes);
	make_token_cursor(token_buf, token_buf + sizeof(token_buf), &tokens);

	ok = read_file(filename, file_buf, sizeof(file_buf), &count);

	if (!ok) {
		printf("failed to load '%s'\n", filename);
		return 0;
	}

	ok = tokenize_cells(file_buf, count, &tokens);

	if (!ok) {
		printf("failed to tokenize\n");
		return 0;
	}

	assert(tokens.c.p == token_buf);

	ok = parse_cell(parser, root);
	if (!ok) {
		print_token_error(&tokens);
		return 0;
	}

	return 1;
}

static int describe(struct parser *parser, u16 root_cell)
{
	static char strbuf[2048];
	struct cursor strs;
	struct cell *cell;

	strbuf[0] = 0;

	cell = get_cell(parser->cells, root_cell);

	make_cursor((u8*)strbuf, (u8*)strbuf + sizeof(strbuf), &strs);

	describe_cells(cell, parser, &strs, 10, 0);

	printf("\n\ndescription\n-----------\n\n%s\n", strbuf);

	return 1;
}

static int usage(void)
{
	printf("usage: protoverse <command> [args]\n\n");
	printf("   COMMANDS\n\n");
	printf("       parse file.space\n");
	printf("       serve file.space\n");
	printf("       client\n");

	return 1;
}

int main(int argc, const char *argv[])
{
	const char *space;
	const char *cmd;
	struct parser parser;
	u16 root;
	int ok;

	if (argc < 2)
		return usage();

	cmd = argv[1];

	if (streq(cmd, "parse")) {
		if (argc != 3)
			return usage();
		space = argv[2];
		ok = parse_file(&parser, space, &root);
		if (!ok) return 1;

		print_cell_tree(&parser, root, 0);

		describe(&parser, root);
	} else if (streq(cmd, "serve")) {
		if (argc != 3)
			return usage();
		space = argv[2];
		printf("serving protoverse on port 1988...\n");
		protoverse_serve("127.0.0.1", 1988);
	} else if (streq(cmd, "client")) {
		protoverse_connect("127.0.0.1", 1988);
	}

	return 0;
}

