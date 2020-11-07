
#include "io.h"
#include "parse.h"
#include "describe.h"
#include "serve.h"
#include "client.h"

#include <assert.h>
#include <stdlib.h>
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


	struct cell *cell = get_cell(&parser->cells, root);
	if (!cell) {
		printf("no root cell...\n");
		return 0;
	}

	/*  sanity TODO: configurable max depth */
	if (depth > 255)
		return 0;

	for (i = 0; i < depth; i++) {
		printf("  ");
	}

	print_cell(&parser->attributes, cell);

	for (i = 0; i < cell->n_children; i++) {
		print_cell_tree(parser, cell->children[i], depth+1);
	}


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
	struct protoverse_server server;
	u16 root;
	int ok;

	if (argc < 2)
		return usage();

	cmd = argv[1];

	if (streq(cmd, "parse")) {
		if (argc != 3)
			return usage();
		ok = init_parser(&parser);
		if (!ok) return 1;
		space = argv[2];
		ok = parse_file(&parser, space, &root);
		if (!ok) return 1;

		print_cell_tree(&parser, root, 0);

		describe(&parser, root);
		free_parser(&parser);
	} else if (streq(cmd, "serve")) {
		if (argc != 3)
			return usage();
		space = argv[2];
		printf("serving protoverse on port 1988...\n");

		server.port = 1988;
		server.bind = "127.0.0.1";

		protoverse_serve(&server);
	} else if (streq(cmd, "client")) {
		protoverse_connect("127.0.0.1", 1988);
	}

	return 0;
}
