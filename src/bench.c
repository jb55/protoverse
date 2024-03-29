#include <time.h>
#include <stdlib.h>
#include <assert.h>
#include <sys/mman.h>

#include "io.h"
#include "wasm.h"

static int bench_wasm(unsigned char *wasm, unsigned long len, int times,
		int argc, const char **argv, char **env)
{
	struct wasm_parser p;
	struct wasm_interp interp;
	struct timespec t1, t2;
	int i, ops = 0;
	int retval;
	long nanos, ms;

	wasm_parser_init(&p, wasm, len, len*16);

	if (!parse_wasm(&p)) {
		return 0;
	}

	if (!wasm_interp_init(&interp, &p.module)) {
		print_error_backtrace(&interp.errors);
		return 0;
	}
	interp.errors.enabled = 0;

	setup_wasi(&interp, argc, argv, env);

	clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &t1);
	for (i = 0; i < times; i++) {
		if (!interp_wasm_module(&interp, &retval)) {
			print_error_backtrace(&interp.errors);
		}
		ops += interp.ops;
	}
	clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &t2);

	nanos = (t2.tv_sec - t1.tv_sec) * (long)1e9 + (t2.tv_nsec - t1.tv_nsec);
	ms = nanos / 1e6;
	printf("ns/run\t%ld\nms/run\t%f\nns\t%ld\nms\t%ld\nops\t%d\nns/op\t%ld\n",
		nanos/times, (double)ms/(double)times, nanos, ms, ops, nanos/(ops+1));

	wasm_interp_free(&interp);
	wasm_parser_free(&p);
	return 1;
}

int main(int argc, char *argv[], char **env)
{
	unsigned char *wasm_data;
	const char *code_file;
	size_t len;
	int times;
	int args = 0;

	if (argc >= 2) {
		args++;
		code_file = argv[1];
	}
	else
		code_file = "wasm/hello.wasm";

	if (argc >= 3) {
		args++;
		times = atoi(argv[2]);
	}
	else
		times = 10000;

	if (!map_file(code_file, &wasm_data, &len)) {
		perror("mmap");
		return 1;
	}
	fprintf(stderr, "executing %s %d times\n", code_file, times);
	if (!bench_wasm(wasm_data, len, times, argc-args,
				((const char**)argv)+args, env)) {
		return 2;
	}

	munmap(wasm_data, len);

	return 0;
}

