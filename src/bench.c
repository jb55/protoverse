#include <time.h>
#include <stdlib.h>
#include <assert.h>
#include <sys/mman.h>

#include "io.h"
#include "wasm.h"

static int bench_wasm(unsigned char *wasm, unsigned long len, int times)
{
	struct wasm_parser p;
	void *mem;
	int arena_size, i, ops = 0;
	struct wasm_interp interp;
	struct timespec t1, t2;
	long nanos, ms;

	arena_size = len * 16;
	memset(&p, 0, sizeof(p));
	mem = malloc(arena_size);
	assert(mem);

	make_cursor(wasm, wasm + len, &p.cur);
	make_cursor(mem, mem + arena_size, &p.mem);

	if (!parse_wasm(&p)) {
		free(mem);
		return 0;
	}

	wasm_interp_init(&interp);

	clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &t1);
	for (i = 0; i < times; i++) {
		if (!interp_wasm_module(&interp, &p.module)) {
			printf("bench: interp_wasm_module failed\n");
			break;
		}
		ops += interp.ops;
	}
	clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &t2);

	nanos = (t2.tv_sec - t1.tv_sec) * (long)1e9 + (t2.tv_nsec - t1.tv_nsec);
	ms = nanos / 1e6;
	printf("ns/run\t%ld\nms/run\t%f\nns\t%ld\nms\t%ld\nops\t%d\nns/op\t%ld\n",
		nanos/times, (double)ms/(double)times, nanos, ms, ops, nanos/ops);

	wasm_interp_free(&interp);

	free(mem);
	return 1;
}

int main(int argc, char *argv[])
{
	unsigned char *wasm_data;
	const char *code_file;
	size_t len;
	int times;

	if (argc >= 2)
		code_file = argv[1];
	else
		code_file = "wasm/hello.wasm";

	if (argc >= 3)
		times = atoi(argv[2]);
	else
		times = 10000;

	if (!map_file(code_file, &wasm_data, &len)) {
		perror("mmap");
		return 1;
	}
	fprintf(stderr, "executing %s %d times\n", code_file, times);
	if (!bench_wasm(wasm_data, len, times)) {
		return 2;
	}

	munmap(wasm_data, len);

	return 0;
}

