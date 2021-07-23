
#include "io.h"
#include "parse.h"
#include "describe.h"
#include "serve.h"
#include "client.h"
#include "wasm.h"
#include "resource.h"
#include "entity.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

#define MAX_ENTITIES 1048576
#define streq(a, b) strcmp(a,b) == 0

/*
static void print_all_cells(struct parser *parser)
{
	struct cell *cell;
	int i, j;
	int ncells;

	ncells = cursor_count(parser->cells, sizeof(struct cell));
	printf("ncells %d\n", ncells);
	for (i = 0; i < ncells; i++) {
		cell = get_cell(parser->cells, i);
		print_cell(parser->attributes, cell);
		printf("\n");

		for (j = 0; j < cell->n_children; j++) {
			cell = get_cell(parser->cells, cell->children[j]);
			assert(cell);
			printf("  ");
			print_cell(parser->attributes, cell);
			printf("\n");
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
	printf("\n");

	for (i = 0; i < cell->n_children; i++) {
		print_cell_tree(parser, cell->children[i], depth+1);
	}


	return 1;
}

static void init_protoverse_server(struct protoverse_server *server)
{
	(void)server;
	/*
	init_resource_manager(&server->env.entities, sizeof(struct entity),
			1024, MAX_ENTITIES, "entity");
			*/
}

static void free_protoverse_server(struct protoverse_server *server)
{
	(void)server;
	//destroy_resource_manager(&server->env.entities);
}

static int usage(void)
{
	printf("usage: protoverse <command> [args]\n\n");
	printf("   COMMANDS\n\n");
	printf("       parse file.space\n");
	printf("       serve file.space\n");
	printf("       client\n");
	printf("       run code.wasm\n");

	return 1;
}



int main(int argc, const char *argv[])
{
	const char *space, *code_file;
	const char *cmd;
	unsigned char *wasm_data;
	struct parser parser;
	struct protoverse_server server;
	u16 root;
	int ok;
	size_t len;

	if (argc < 2)
		return usage();

	cmd = argv[1];

	if (streq(cmd, "parse")) {
		if (argc != 3)
			return usage();
		ok = init_parser(&parser);
		if (!ok) {
			printf("failed to initialize parser\n");
			return 1;
		}
		space = argv[2];
		ok = parse_file(&parser, space, &root);
		if (!ok) {
			printf("failed to parse file\n");
			return 1;
		}

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

		init_protoverse_server(&server);
		protoverse_serve(&server);
		free_protoverse_server(&server);
	} else if (streq(cmd, "client")) {
		protoverse_connect("127.0.0.1", 1988);
	} else if (streq(cmd, "run")) {
		if (argc < 3)
			return usage();
		code_file = argv[2];
		if (!map_file(code_file, &wasm_data, &len)) {
			perror("mmap");
			return 1;
		}
		if (!run_wasm(wasm_data, len, argc - 2, argv + 2)) {
			return 2;
		}
		munmap(wasm_data, len);
	}

	return 0;
}
